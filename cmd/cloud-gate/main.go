package main

import (
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Symantec/Dominator/lib/log/debuglogger"
	"github.com/Symantec/Dominator/lib/log/serverlogger"
	"github.com/Symantec/Dominator/lib/log/teelogger"
	"github.com/Symantec/cloud-gate/broker"
	"github.com/Symantec/cloud-gate/broker/aws"
	"github.com/Symantec/cloud-gate/broker/configuration"
	"github.com/Symantec/cloud-gate/broker/httpd"
	"github.com/Symantec/cloud-gate/broker/staticconfiguration"
	"github.com/Symantec/cloud-gate/lib/userinfo/ldap"
	"github.com/Symantec/tricorder/go/tricorder"
)

var (
	configFilename = flag.String("config", "/etc/cloud-gate/static-config.yml", "Configuration filename")
)

func main() {
	flag.Parse()
	tricorder.RegisterFlags()
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "Do not run the cloud-gate server as root")
		os.Exit(1)
	}
	logger := serverlogger.New("")

	syslogWriter, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_NOTICE, "cloud-gate")
	if err != nil {
		logger.Printf("Could not open connection to local syslog daemon")
		syslogWriter = nil
	}
	auditLogger := teelogger.New(logger, debuglogger.Upgrade(log.New(syslogWriter, "", 0)))

	staticConfig, err := staticconfiguration.LoadVerifyConfigFile(*configFilename)
	if err != nil {
		logger.Fatalf("Cannot load Configuration: %s\n", err)
	}
	logger.Debugf(1, "staticconfig=%+v", staticConfig)

	timeoutSecs := 15
	userInfo, err := ldap.New(strings.Split(staticConfig.Ldap.LDAPTargetURLs, ","),
		staticConfig.Ldap.BindUsername,
		staticConfig.Ldap.BindPassword,
		staticConfig.Ldap.UserSearchFilter,
		staticConfig.Ldap.UserSearchBaseDNs,
		uint(timeoutSecs), nil, logger)
	if err != nil {
		logger.Fatalf("Cannot create ldap userinfo: %s\n", err)
	}
	logger.Debugf(1, "userinfo=%+v", userInfo)

	configCacheFilename := filepath.Join(staticConfig.Base.DataDirectory, "accounts-cache.yml")
	configChannel, err := configuration.Watch(staticConfig.Base.AccountConfigurationUrl,
		configCacheFilename,
		staticConfig.Base.AccountConfigurationCheckInterval, logger)
	if err != nil {
		logger.Fatalf("Cannot watch for configuration: %s\n", err)
	}

	brokers := map[string]broker.Broker{
		"aws": aws.New(userInfo, staticConfig.Base.AWSCredentialsFilename,
			staticConfig.Base.AWSListRolesRoleName,
			logger, auditLogger),
	}
	for brokerName, broker := range brokers {
		err = broker.LoadCredentialsFile()
		if err != nil {
			logger.Fatalf("Could not load broker for %s: %s\n", brokerName, err)
		}
	}

	webServer, err := httpd.StartServer(staticConfig, userInfo, brokers, logger)
	if err != nil {
		logger.Fatalf("Unable to create http server: %s\n", err)
	}
	webServer.AddHtmlWriter(logger)

	isReadyMetric := prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "cloudgate_isReady",
			Help: "Cloudgate is unsealed and ready to accept connections",
		},
		func() float64 {
			if webServer.GetIsReady() {
				return 1.0
			}
			return 0.0
		},
	)
	prometheus.MustRegister(isReadyMetric)

	go func() {
		logger.Debugf(1, "starting wait for unsealing")
		//wait for all brokers to be unsealed
		for _, broker := range brokers {
			c, err := broker.GetIsUnsealedChannel()
			if err != nil {
				logger.Fatalf("cannot get unsealing channel%s\n", err)
			}
			isUnsealed := <-c
			if isUnsealed != nil {
				logger.Fatalf("broker unsealing error%s\n", err)
			}
		}
		logger.Debugf(1, "Unsealing done, starting service port")
		err = webServer.StartServicePort()
		if err != nil {
			logger.Fatalf("Unable to start Service Port: %s\n", err)
		}
	}()
	for config := range configChannel {
		logger.Println("Received new configuration")
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
