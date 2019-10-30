package aws

import (
	stdlog "log"
	"os"
	"testing"
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/log/debuglogger"
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

//same as above but encrypted with passphrase "password"
const encryptedValidCredentials = `-----BEGIN PGP MESSAGE-----
Comment: GPGTools - http://gpgtools.org

jA0EBwMCPUCLUmxQYZvk0p0BFvgNP64N/PJY88/iC4599KKOIVvf44ceHsUqrg1q
vS2FjMr4itQUd0e1j9mGFNNUMsHZDQ2mlB+yl9ZcfI3LfGiav/Uln7+iLlgSBNwH
6YUWOLIg432i6KL5sD1jxasL+3ubzZoxia+g2Q240L82HcAWCnaCVv/z+2FnR7t4
Gx3fQbU0jBkntZw2bHeUZnryMu6TC9hmyLl0q/Rz
=Dp5J
-----END PGP MESSAGE-----`

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
	b := setupCachedBroker()
	c1, err := b.GetIsUnsealedChannel()
	if err != nil {
		t.Fatal(err)
	}
	err = b.loadCredentialsFrombytes([]byte(validTestPlaintextCredentials))
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

func TestUnsealingSucess(t *testing.T) {
	b := setupCachedBroker()

	c1, err := b.GetIsUnsealedChannel()
	if err != nil {
		t.Fatal(err)
	}

	b.rawCredentialsFile = []byte(encryptedValidCredentials)
	_, err = b.ProcessNewUnsealingSecret("password")
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
