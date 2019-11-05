package main

import (
	"errors"
	"flag"
	"fmt"
	stdlog "log"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Cloud-Foundations/Dominator/lib/log"
	"github.com/Cloud-Foundations/Dominator/lib/log/debuglogger"
	"github.com/Cloud-Foundations/Dominator/lib/log/serverlogger"
	"github.com/Cloud-Foundations/Dominator/lib/log/teelogger"
	"github.com/Cloud-Foundations/tricorder/go/tricorder"
	"github.com/Symantec/cloud-gate/broker"
	"github.com/Symantec/cloud-gate/broker/aws"
	"github.com/Symantec/cloud-gate/broker/configuration"
	"github.com/Symantec/cloud-gate/broker/httpd"
	"github.com/Symantec/cloud-gate/broker/staticconfiguration"
	"github.com/Symantec/cloud-gate/lib/userinfo"
	"github.com/Symantec/cloud-gate/lib/userinfo/gitdb"
	"github.com/Symantec/cloud-gate/lib/userinfo/ldap"
)

var (
	configFilename = flag.String("config", "/etc/cloud-gate/static-config.yml",
		"Configuration filename")
)

func getUserInfo(config *staticconfiguration.StaticConfiguration,
	logger log.DebugLogger) (userinfo.UserInfo, error) {
	if config.Ldap.LDAPTargetURLs != "" {
		timeoutSecs := 15
		userInfo, err := ldap.New(
			strings.Split(config.Ldap.LDAPTargetURLs, ","),
			config.Ldap.BindUsername,
			config.Ldap.BindPassword,
			config.Ldap.UserSearchFilter,
			config.Ldap.UserSearchBaseDNs,
			uint(timeoutSecs), nil, logger)
		if err != nil {
			return nil, fmt.Errorf("cannot create ldap userinfo: %s", err)
		}
		return userInfo, nil
	}
	if config.GitDB.LocalRepositoryDirectory != "" {
		userInfo, err := gitdb.New(config.GitDB.RepositoryURL,
			config.GitDB.LocalRepositoryDirectory,
			config.GitDB.CheckInterval, logger)
		if err != nil {
			return nil, fmt.Errorf("cannot create GitDB userinfo: %s", err)
		}
		return userInfo, nil
	}
	return nil, errors.New("no userinfo database specified")
}

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
	auditLogger := teelogger.New(logger,
		debuglogger.Upgrade(stdlog.New(syslogWriter, "", 0)))

	staticConfig, err := staticconfiguration.LoadVerifyConfigFile(*configFilename)
	if err != nil {
		logger.Fatalf("Cannot load Configuration: %s\n", err)
	}
	logger.Debugf(1, "staticconfig=%+v", staticConfig)

	userInfo, err := getUserInfo(staticConfig, logger)
	if err != nil {
		logger.Fatalln(err)
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
