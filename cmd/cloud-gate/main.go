package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Symantec/Dominator/lib/log/serverlogger"
	"github.com/Symantec/cloud-gate/broker"
	"github.com/Symantec/cloud-gate/broker/aws"
	"github.com/Symantec/cloud-gate/broker/configuration"
	"github.com/Symantec/cloud-gate/broker/httpd"
	"github.com/Symantec/tricorder/go/tricorder"
)

var (
	configurationCheckInterval = flag.Duration("configurationCheckInterval",
		time.Minute*5, "Configuration check interval")
	configurationUrl = flag.String("configurationUrl",
		"file:///etc/cloud-gate/conf.json", "URL containing configuration")
	portNum = flag.Uint("portNum", 443,
		"Port number to allocate and listen on for HTTP/RPC")
)

func main() {
	flag.Parse()
	tricorder.RegisterFlags()
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "Do not run the cloud-gate server as root")
		os.Exit(1)
	}
	logger := serverlogger.New("")
	configChannel, err := configuration.Watch(*configurationUrl,
		*configurationCheckInterval, logger)
	if err != nil {
		logger.Fatalf("Cannot watch for configuration: %s\n", err)
	}
	brokers := map[string]broker.Broker{
		"aws": aws.New(logger),
	}
	webServer, err := httpd.StartServer(*portNum, brokers, logger)
	if err != nil {
		logger.Fatalf("Unable to create http server: %s\n", err)
	}
	for config := range configChannel {
		if err := webServer.UpdateConfiguration(config); err != nil {
			logger.Println(err)
		}
		for _, broker := range brokers {
			if err := broker.UpdateConfiguration(config); err != nil {
				logger.Println(err)
			}
		}
	}
}
