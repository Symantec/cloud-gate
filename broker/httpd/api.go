package httpd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/Dominator/lib/log/serverlogger"
	"github.com/Symantec/Dominator/lib/logbuf"
	"github.com/Symantec/cloud-gate/broker"
	"github.com/Symantec/cloud-gate/broker/configuration"
	"github.com/Symantec/cloud-gate/broker/staticconfiguration"
	"github.com/Symantec/cloud-gate/lib/constants"
	"github.com/Symantec/cloud-gate/lib/userinfo"
)

type HtmlWriter interface {
	WriteHtml(writer io.Writer)
}

type AuthCookie struct {
	Username  string
	ExpiresAt time.Time
}

type Server struct {
	brokers      map[string]broker.Broker
	config       *configuration.Configuration
	htmlWriters  []HtmlWriter
	htmlTemplate *template.Template
	logger       log.DebugLogger
	cookieMutex  sync.Mutex
	authCookie   map[string]AuthCookie
	staticConfig *staticconfiguration.StaticConfiguration
	userInfo     userinfo.UserInfo
	netClient    *http.Client
	accessLogger log.DebugLogger
	tlsConfig    *tls.Config
	serviceMux   *http.ServeMux
	isReady      bool
}

var authCookieName = constants.AuthCookieName

func (s *Server) mainEntryPointHandler(w http.ResponseWriter, r *http.Request) {
	s.logger.Debugf(3, "top of mainEntryPointHandler")
	if r.URL.Path == "/favicon.ico" {
		w.Header().Set("Cache-Control", "public, max-age=120")
		http.Redirect(w, r, "/custom_static/favicon.ico", http.StatusFound)
		return
	}
	if r.URL.Path != "/" {
		http.Error(w, "error not found", http.StatusNotFound)
		return
	}
	s.consoleAccessHandler(w, r)
}

type httpLogger struct {
	AccessLogger log.DebugLogger
}

func (l httpLogger) Log(record LogRecord) {
	if l.AccessLogger != nil {
		l.AccessLogger.Printf("%s -  %s [%s] \"%s %s %s\" %d %d\n",
			record.Ip, record.Username, record.Time, record.Method,
			record.Uri, record.Protocol, record.Status, record.Size)
	}
}

func StartServer(staticConfig *staticconfiguration.StaticConfiguration,
	userInfo userinfo.UserInfo,
	brokers map[string]broker.Broker,
	logger log.DebugLogger) (*Server, error) {

	authCookieSuffix, err := randomStringGeneration()
	if err != nil {
		return nil, err
	}
	authCookieName = constants.AuthCookieName + "_" + authCookieSuffix[0:6]

	statusListener, err := net.Listen("tcp", fmt.Sprintf(":%d", staticConfig.Base.StatusPort))
	if err != nil {
		return nil, err
	}
	server := &Server{
		brokers:      brokers,
		logger:       logger,
		userInfo:     userInfo,
		staticConfig: staticConfig,
		netClient: &http.Client{
			Timeout: time.Second * 15,
		},
	}
	server.authCookie = make(map[string]AuthCookie)
	go server.performStateCleanup(constants.SecondsBetweenCleanup)

	logBufOptions := logbuf.GetStandardOptions()
	accessLogDirectory := filepath.Join(logBufOptions.Directory, "access")
	server.accessLogger = serverlogger.NewWithOptions("access",
		logbuf.Options{MaxFileSize: 10 << 20,
			Quota: 100 << 20, MaxBufferLines: 100,
			Directory: accessLogDirectory},
		stdlog.LstdFlags)

	// load templates
	templatesPath := filepath.Join(staticConfig.Base.SharedDataDirectory, "customization_data", "templates")
	if _, err = os.Stat(templatesPath); err != nil {
		return nil, err
	}
	server.htmlTemplate = template.New("main")

	templateFiles := []string{"footer_extra.tmpl", "header_extra.tmpl"}
	for _, templateFilename := range templateFiles {
		templatePath := filepath.Join(templatesPath, templateFilename)
		_, err = server.htmlTemplate.ParseFiles(templatePath)
		if err != nil {
			return nil, err
		}
	}

	/// Load the oter built in templates
	extraTemplates := []string{footerTemplateText,
		consoleAccessTemplateText,
		generateTokaneTemplateText,
		unsealingFormPageTemplateText,
		headerTemplateText}
	for _, templateString := range extraTemplates {
		_, err = server.htmlTemplate.Parse(templateString)
		if err != nil {
			return nil, err
		}
	}

	http.HandleFunc("/", server.dashboardRootHandler)
	http.HandleFunc("/status", server.statusHandler)
	http.HandleFunc("/unseal", server.unsealingHandler)
	http.HandleFunc(constants.Oauth2redirectPath, server.oauth2RedirectPathHandler)
	http.Handle("/prometheus_metrics", promhttp.Handler())
	serviceMux := http.NewServeMux()
	serviceMux.HandleFunc("/", server.mainEntryPointHandler)
	serviceMux.HandleFunc("/getconsole", server.getConsoleUrlHandler)
	serviceMux.HandleFunc("/generatetoken", server.generateTokenHandler)
	serviceMux.HandleFunc("/static/", staticHandler)
	customWebResourcesPath := filepath.Join(staticConfig.Base.SharedDataDirectory, "customization_data", "web_resources")
	if _, err = os.Stat(customWebResourcesPath); err == nil {
		serviceMux.Handle("/custom_static/", http.StripPrefix("/custom_static/", http.FileServer(http.Dir(customWebResourcesPath))))
	}
	//setup openidc auth
	serviceMux.HandleFunc(constants.Oauth2redirectPath, server.oauth2RedirectPathHandler)
	server.serviceMux = serviceMux

	var clientCACertPool *x509.CertPool
	if len(staticConfig.Base.ClientCAFilename) > 0 {
		clientCACertPool = x509.NewCertPool()
		caCert, err := ioutil.ReadFile(staticConfig.Base.ClientCAFilename)
		if err != nil {
			logger.Fatalf("cannot read clientCA file err=%s", err)
		}
		clientCACertPool.AppendCertsFromPEM(caCert)
	}

	server.tlsConfig = &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  clientCACertPool,
	}
	l := httpLogger{AccessLogger: server.accessLogger}
	adminSrv := &http.Server{
		Handler:      NewLoggingHandler(http.DefaultServeMux, l),
		TLSConfig:    server.tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		err := adminSrv.ServeTLS(statusListener,
			staticConfig.Base.TLSCertFilename,
			staticConfig.Base.TLSKeyFilename)
		if err != nil {
			logger.Fatalf("Failed to start status server, err=%s", err)
		}
	}()
	return server, nil
}

func (s *Server) StartServicePort() error {
	serviceListener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.staticConfig.Base.ServicePort))
	if err != nil {
		return err
	}
	l := httpLogger{AccessLogger: s.accessLogger}
	serviceServer := &http.Server{
		Handler:      NewLoggingHandler(s.serviceMux, l),
		TLSConfig:    s.tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	c1 := make(chan error, 1)
	go func() {
		err := serviceServer.ServeTLS(serviceListener, s.staticConfig.Base.TLSCertFilename, s.staticConfig.Base.TLSKeyFilename)
		c1 <- err
	}()
	go func() {
		target := fmt.Sprintf("127.0.0.1:%d", s.staticConfig.Base.ServicePort)
		time.Sleep(20 * time.Millisecond)
		timeoutTime := time.Now().Add(1 * time.Second)
		for time.Now().Before(timeoutTime) {
			conn, err := net.DialTimeout("tcp", target, 50*time.Millisecond)
			if err == nil {
				s.isReady = true
				c1 <- nil
				// We do a TLS handshake in order to avoid error reporting in the log
				tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
				defer tlsConn.Close()
				tlsConn.Handshake()
				return
			}
		}
	}()
	select {
	case serveErr := <-c1:
		return serveErr
	case <-time.After(500 * time.Millisecond): //500ms should be enough
		return errors.New("Timout waiting for server to start")
	}
}

func (s *Server) AddHtmlWriter(htmlWriter HtmlWriter) {
	s.htmlWriters = append(s.htmlWriters, htmlWriter)
}

func (s *Server) UpdateConfiguration(
	config *configuration.Configuration) error {
	s.config = config
	return nil
}
