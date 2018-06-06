package ldap

import (
	"crypto/x509"
	//"errors"
	//"fmt"
	//"time"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/keymaster/lib/authutil"
)

func newUserInfo(urllist []string, bindUsername string, bindPassword string,
	userSearchFilter string, userSearchBaseDNs []string, timeoutSecs uint, rootCAs *x509.CertPool, logger log.DebugLogger) (
	*UserInfo, error) {
	var userinfo UserInfo
	for _, stringURL := range urllist {
		url, err := authutil.ParseLDAPURL(stringURL)
		if err != nil {
			return nil, err
		}
		userinfo.ldapURL = append(userinfo.ldapURL, url)
	}
	return &userinfo, nil
}

func (uinfo *UserInfo) getUserGroups(username string, groupPrefix *string) ([]string, error) {
	var groups []string
	return groups, nil
}
