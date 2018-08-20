package broker

import (
	"github.com/Symantec/cloud-gate/broker/configuration"
)

type PermittedAccount struct {
	Name              string
	HumanName         string
	PermittedRoleName []string
}

type Broker interface {
	UpdateConfiguration(config *configuration.Configuration) error
	GetUserAllowedAccounts(username string) ([]PermittedAccount, error)
}
