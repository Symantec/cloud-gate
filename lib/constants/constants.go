package constants

import (
	"time"
)

const (
	DefaultServicePort                       = 443
	DefaultStatusPort                        = 6930
	DefaultAccountConfigurationUrl           = "file:///etc/cloud-gate/accounts.yml"
	DefaultAccountConfigurationCheckInterval = time.Minute * 5
	InitialTimeoutForAccountInfo             = time.Second * 15
)
