package appconfiguration

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	//"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

func LoadVerifyConfigFile(configFilename string) (*AppConfiguration, error) {
	var config *AppConfiguration
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return config, err
	}
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		err = errors.New("cannot read config file")
		return config, err
	}
	log.Printf(string(source[:]))
	err = yaml.Unmarshal(source, config)
	if err != nil {
		err = errors.New("Cannot parse config file")
		return config, err
	}
	return config, nil
}
