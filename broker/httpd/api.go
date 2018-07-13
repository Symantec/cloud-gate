package httpd

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/cloud-gate/broker"
	"github.com/Symantec/cloud-gate/broker/configuration"
	"github.com/Symantec/cloud-gate/broker/staticconfiguration"
)

type HtmlWriter interface {
	WriteHtml(writer io.Writer)
}

type Server struct {
	brokers      map[string]broker.Broker
	config       *configuration.Configuration
	htmlWriters  []HtmlWriter
	htmlTemplate *template.Template
	staticConfig *staticconfiguration.StaticConfiguration

	logger log.DebugLogger
}

func StartServer(staticConfig *staticconfiguration.StaticConfiguration, brokers map[string]broker.Broker,
	logger log.DebugLogger) (*Server, error) {

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
		staticConfig: staticConfig,
	}
	// load templates
	server.htmlTemplate = template.New("main")
	// Load the other built in templates
	extraTemplates := []string{footerTemplateText, consoleAccessTemplateText, headerTemplateText}
	for _, templateString := range extraTemplates {
		_, err = server.htmlTemplate.Parse(templateString)
		if err != nil {
			return nil, err
		}
	}

	http.HandleFunc("/", server.dashboardRootHandler)
	http.HandleFunc("/status", server.statusHandler)
	serviceMux := http.NewServeMux()
	serviceMux.HandleFunc("/", server.consoleAccessHandler)
	serviceMux.HandleFunc("/static/", staticHandler)

	statusServer := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		err := statusServer.Serve(statusListener)
		if err != nil {
			logger.Fatalf("Failed to start status server, err=%s", err)
		}
	}()
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	serviceServer := &http.Server{
		Handler:      serviceMux,
		TLSConfig:    tlsConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
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
