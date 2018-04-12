package broker

import (
	"github.com/Symantec/cloud-gate/broker/configuration"
)

type Broker interface {
	UpdateConfiguration(config *configuration.Configuration) error
}
