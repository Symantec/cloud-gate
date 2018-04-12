package aws

import (
	"errors"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/cloud-gate/broker/configuration"
)

type Broker struct {
	config *configuration.Configuration
	logger log.DebugLogger
}

func New(logger log.DebugLogger) *Broker {
	return &Broker{logger: logger}
}

func (b *Broker) UpdateConfiguration(
	config *configuration.Configuration) error {
	return errors.New("not implemented")
}
