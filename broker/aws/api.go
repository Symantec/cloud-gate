package aws

import (
	"errors"
	"sync"
	"time"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/cloud-gate/broker"
	"github.com/Symantec/cloud-gate/broker/configuration"
	"github.com/Symantec/cloud-gate/lib/userinfo"
)

type userAllowedCredentialsCacheEntry struct {
	PermittedAccounts []broker.PermittedAccount
	Expiration        time.Time
}

type accountRoleCacheEntry struct {
	Roles      []string
	Expiration time.Time
}

type Broker struct {
	config                      *configuration.Configuration
	userInfo                    userinfo.UserInfo
	credentialsFilename         string
	logger                      log.DebugLogger
	auditLogger                 log.DebugLogger
	userAllowedCredentialsCache map[string]userAllowedCredentialsCacheEntry
	userAllowedCredentialsMutex sync.Mutex
	accountRoleCache            map[string]accountRoleCacheEntry
	accountRoleMutex            sync.Mutex
}

func New(userInfo userinfo.UserInfo,
	credentialsFilename string,
	logger log.DebugLogger, auditLogger log.DebugLogger) *Broker {
	return &Broker{userInfo: userInfo,
		credentialsFilename:         credentialsFilename,
		logger:                      logger,
		auditLogger:                 auditLogger,
		userAllowedCredentialsCache: make(map[string]userAllowedCredentialsCacheEntry),
		accountRoleCache:            make(map[string]accountRoleCacheEntry),
	}
}

func (b *Broker) UpdateConfiguration(
	config *configuration.Configuration) error {
	if config == nil {
		return errors.New("nill config passed")
	}
	b.logger.Debugf(1, "config=%+v", *config)
	b.config = config
	return nil
}

func (b *Broker) GetUserAllowedAccounts(username string) ([]broker.PermittedAccount, error) {
	return b.getUserAllowedAccounts(username)
}

func (b *Broker) IsUserAllowedToAssumeRole(username string, accountName string, roleName string) (bool, error) {
	return b.isUserAllowedToAssumeRole(username, accountName, roleName)
}

func (b *Broker) GetConsoleURLForAccountRole(accountName string, roleName string, userName string) (string, error) {
	return b.getConsoleURLForAccountRole(accountName, roleName, userName)
}

func (b *Broker) GenerateTokenCredentials(accountName string, roleName string, userName string) (*broker.AWSCredentialsJSON, error) {
	return b.generateTokenCredentials(accountName, roleName, userName)
}
