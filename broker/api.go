package broker

import (
	"time"

	"github.com/Symantec/cloud-gate/broker/configuration"
)

type PermittedAccount struct {
	Name              string
	HumanName         string
	PermittedRoleName []string
}

type AWSCredentialsJSON struct {
	SessionId    string    `json:"sessionId"`
	SessionKey   string    `json:"sessionKey"`
	SessionToken string    `json:"sessionToken"`
	Region       string    `json:"region,omitempty"`
	Expiration   time.Time `json:"cloudgate_comment_expiration,omitempty"`
}

type Broker interface {
	UpdateConfiguration(config *configuration.Configuration) error
	GetUserAllowedAccounts(username string) ([]PermittedAccount, error)
	UserAllowedToAssumeRole(username string, accountName string, roleName string) (bool, error)
	GetConsoleURLForAccountRole(accountName string, roleName string, username string, issuerURL string) (string, error)
	GenerateTokenCredentials(accountName string, roleName string, username string) (*AWSCredentialsJSON, error)
	ProcessNewUnsealingSecret(secret string) (ready bool, err error)
	GetIsUnsealedChannel() (<-chan error, error)
	LoadCredentialsFile() error
}
