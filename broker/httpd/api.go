package httpd

import (
	"fmt"
	"net"
	"net/http"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/cloud-gate/broker"
	"github.com/Symantec/cloud-gate/broker/configuration"
)

type Server struct {
	brokers map[string]broker.Broker
	config  *configuration.Configuration
	logger  log.DebugLogger
}

func StartServer(portNum uint, brokers map[string]broker.Broker,
	logger log.DebugLogger) (*Server, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portNum))
	if err != nil {
		return nil, err
	}
	server := &Server{
		brokers: brokers,
		logger:  logger,
	}
	// http.HandleFunc("/", server.rootHandler)
	go http.Serve(listener, nil)
	return server, nil
}

func (s *Server) UpdateConfiguration(
	config *configuration.Configuration) error {
	s.config = config
	return nil
}
