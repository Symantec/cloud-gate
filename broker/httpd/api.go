package httpd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/cloud-gate/broker"
	"github.com/Symantec/cloud-gate/broker/configuration"
	"github.com/Symantec/cloud-gate/broker/staticconfiguration"
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
}

const secondsBetweenCleanup = 60
const cookieExpirationHours = 3
const maxAgeSecondsRedirCookie = 120
const redirCookieName = "oauth2_redir"
const oauth2redirectPath = "/oauth2/redirectendpoint"

var authCookieName = "auth_cookie"

func (s *Server) performStateCleanup(secsBetweenCleanup int) {
	for {
		s.cookieMutex.Lock()
		for key, authCookie := range s.authCookie {
			if authCookie.ExpiresAt.Before(time.Now()) {
				delete(s.authCookie, key)
			}
		}
		s.cookieMutex.Unlock()
		time.Sleep(time.Duration(secsBetweenCleanup) * time.Second)
	}

}

func (s *Server) mainEntryPointHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
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
}

func (l httpLogger) Log(record LogRecord) {
	fmt.Printf("%s -  %s [%s] \"%s %s %s\" %d %d\n",
		record.Ip, record.Username, record.Time, record.Method,
		record.Uri, record.Protocol, record.Status, record.Size)
}

func StartServer(staticConfig *staticconfiguration.StaticConfiguration,
	userInfo userinfo.UserInfo,
	brokers map[string]broker.Broker,
	logger log.DebugLogger) (*Server, error) {

	authCookieSuffix, err := randomStringGeneration()
	if err != nil {
		return nil, err
	}
	authCookieName = authCookieName + "_" + authCookieSuffix[0:6]

	statusListener, err := net.Listen("tcp", fmt.Sprintf(":%d", staticConfig.Base.StatusPort))
	if err != nil {
		return nil, err
	}
	serviceListener, err := net.Listen("tcp", fmt.Sprintf(":%d", staticConfig.Base.ServicePort))
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
	go server.performStateCleanup(secondsBetweenCleanup)

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
	extraTemplates := []string{footerTemplateText, consoleAccessTemplateText, generateTokaneTemplateText, headerTemplateText}
	for _, templateString := range extraTemplates {
		_, err = server.htmlTemplate.Parse(templateString)
		if err != nil {
			return nil, err
		}
	}

	http.HandleFunc("/", server.rootHandler)
	http.HandleFunc("/status", server.statusHandler)
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
	serviceMux.HandleFunc(oauth2redirectPath, server.oauth2RedirectPathHandler)

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	adminSrv := &http.Server{
		TLSConfig:    cfg,
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

	var clientCACertPool *x509.CertPool
	if len(staticConfig.Base.ClientCAFilename) > 0 {
		clientCACertPool = x509.NewCertPool()
		caCert, err := ioutil.ReadFile(staticConfig.Base.ClientCAFilename)
		if err != nil {
			logger.Fatalf("cannot read clientCA file err=%s", err)
		}
		clientCACertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
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
	l := httpLogger{}
	serviceServer := &http.Server{
		Handler:      NewLoggingHandler(serviceMux, l),
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		err := serviceServer.ServeTLS(serviceListener, staticConfig.Base.TLSCertFilename, staticConfig.Base.TLSKeyFilename)
		if err != nil {
			logger.Fatalf("Failed to start service server, err=%s", err)
		}
	}()
	return server, nil
}

func (s *Server) AddHtmlWriter(htmlWriter HtmlWriter) {
	s.htmlWriters = append(s.htmlWriters, htmlWriter)
}

func (s *Server) UpdateConfiguration(
	config *configuration.Configuration) error {
	s.config = config
	return nil
}
