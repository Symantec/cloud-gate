package staticconfiguration

import (
	"errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

const defaultServicePort = 443
const defaultStatusPort = 6930
const defaultAccountConfigurationUrl = "file:///etc/cloud-gate/accounts.yml"

func LoadVerifyConfigFile(configFilename string) (*StaticConfiguration, error) {
	var config StaticConfiguration
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return nil, err
	}
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		err = errors.New("cannot read config file")
		return nil, err
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		err = errors.New("Cannot parse config file")
		return nil, err
	}
	// setup defaults
	if config.Base.StatusPort == 0 {
		config.Base.StatusPort = defaultStatusPort
	}
	if config.Base.ServicePort == 0 {
		config.Base.ServicePort = defaultServicePort
	}
	if len(config.Base.AccountConfigurationUrl) == 0 {
		config.Base.AccountConfigurationUrl = defaultAccountConfigurationUrl
	}

	return &config, nil
}
