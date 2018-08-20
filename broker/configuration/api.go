package configuration

import (
	"time"

	"github.com/Symantec/Dominator/lib/log"
)

type AWSAccount struct {
	Name           string   `yaml:"name"`
	AccountID      string   `yaml:"account_id"`
	DisplayName    string   `yaml:"display_name"`
	GroupName      string   `yaml:"group_name"`
	ExtraUserRoles []string `yaml:"extra_user_roles"`
}

type AWSConfiguration struct {
	GroupPrefix string       `yaml:"group_prefix"`
	Account     []AWSAccount `yaml:"account"`
}

type Configuration struct {
	AWS AWSConfiguration `yaml:"aws"`
}

func Watch(configUrl string, checkInterval time.Duration,
	logger log.DebugLogger) (<-chan *Configuration, error) {
	return watch(configUrl, checkInterval, logger)
}
