package appconfiguration

import (
	"errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

const defaultServicePort = 443
const defaultStatusPort = 6930

func LoadVerifyConfigFile(configFilename string) (*AppConfiguration, error) {
	var config AppConfiguration
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

	return &config, nil
}
