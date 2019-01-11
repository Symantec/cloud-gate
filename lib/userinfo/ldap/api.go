package ldap

import (
	"crypto/x509"
	"net/url"

	"github.com/Symantec/Dominator/lib/log"
)

type UserInfo struct {
	ldapURL           []*url.URL
	bindUsername      string
	bindPassword      string
	userSearchFilter  string
	userSearchBaseDNs []string
	timeoutSecs       uint
	rootCAs           *x509.CertPool
	logger            log.DebugLogger
}

func New(url []string, bindUsername string, bindPassword string,
	userSearchFilter string, userSearchBaseDNs []string, timeoutSecs uint, rootCAs *x509.CertPool, logger log.DebugLogger) (
	*UserInfo, error) {
	return newUserInfo(url, bindUsername, bindPassword, userSearchFilter, userSearchBaseDNs, timeoutSecs, rootCAs, logger)
}

func (uinfo *UserInfo) GetUserGroups(username string, groupPrefix *string) ([]string, error) {
	return uinfo.getUserGroups(username, groupPrefix)
}
