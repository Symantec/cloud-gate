package aws

import (
	stdlog "log"
	"os"
	"testing"
	"time"

	"github.com/Symantec/Dominator/lib/log/debuglogger"
	"github.com/Symantec/cloud-gate/broker"
)

const validTestPlaintextCredentials = `
[broker-master]
aws_access_key_id = aaaaaaaaaaaaaaaa
aws_secret_access_key = asdasdasdasdasdsad

[other-account]
aws_access_key_id = bbbbbbbbbbbbbbbb
aws_secret_access_key = asdasdasdasdasdsad
region = us-east-1
`

func setupCachedBroker() *Broker {
	slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	logger := debuglogger.New(slogger)
	b := &Broker{ //userInfo: userInfo,
		//credentialsFilename:         credentialsFilename,
		logger: logger,
		//syslog:                      syslog,
		userAllowedCredentialsCache: make(map[string]userAllowedCredentialsCacheEntry),
		accountRoleCache:            make(map[string]accountRoleCacheEntry),
		isUnsealedChannel:           make(chan error, 1),
		profileCredentials:          make(map[string]awsProfileEntry),
	}

	demoAccountEntry := broker.PermittedAccount{Name: "demoAccount",
		HumanName: "Demo Account", PermittedRoleName: []string{"ro-ccount"}}
	demoUserCachedEntry := userAllowedCredentialsCacheEntry{
		PermittedAccounts: []broker.PermittedAccount{demoAccountEntry},
		Expiration:        time.Now().Add(time.Second * 30),
	}
	b.userAllowedCredentialsCache["demouser"] = demoUserCachedEntry

	return b
}

func TestLoadCredentialsFrombytesSuccess(t *testing.T) {
	broker := setupCachedBroker()
	c1, err := broker.GetIsUnsealedChannel()
	if err != nil {
		t.Fatal(err)
	}
	err = broker.loadCredentialsFrombytes([]byte(validTestPlaintextCredentials))
	if err != nil {
		t.Fatal(err)
	}

	select {
	case unsealErr := <-c1:
		if unsealErr != nil {
			t.Fatal(unsealErr)
		}
	case <-time.After(500 * time.Millisecond): //500ms should be enough
		t.Fatal("too slow")
	}

}
