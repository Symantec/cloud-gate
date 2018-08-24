package ldap

import (
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"

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
	userinfo.bindUsername = bindUsername
	userinfo.bindPassword = bindPassword
	userinfo.userSearchFilter = userSearchFilter
	userinfo.userSearchBaseDNs = userSearchBaseDNs
	userinfo.timeoutSecs = timeoutSecs
	userinfo.rootCAs = rootCAs
	userinfo.logger = logger
	return &userinfo, nil
}

func (uinfo *UserInfo) extractCNFromDNString(input []string, groupPrefix string) (output []string, err error) {
	reString := fmt.Sprintf("^CN=%s([^,]+),.*", groupPrefix)
	re, err := regexp.Compile(reString)
	if err != nil {
		return nil, err
	}
	uinfo.logger.Debugf(1, "input=%v ", input)
	for _, dn := range input {
		matches := re.FindStringSubmatch(dn)
		if len(matches) == 2 {
			output = append(output, matches[1])
		} else {
			uinfo.logger.Debugf(5, "Not matching dn='%s' matches=%v", dn, matches)
			//output = append(output, dn)
		}
	}
	return output, nil

}

func (uinfo *UserInfo) getUserGroups(username string, groupPrefix *string) ([]string, error) {
	attributesOfInterest := []string{"memberOf", "mail"}
	ldapSuccess := false
	var userAttributes map[string][]string
	var err error
	for _, ldapUrl := range uinfo.ldapURL {
		userAttributes, err = authutil.GetLDAPUserAttributes(*ldapUrl, uinfo.bindUsername, uinfo.bindPassword,
			uinfo.timeoutSecs, uinfo.rootCAs,
			username,
			uinfo.userSearchBaseDNs, uinfo.userSearchFilter,
			attributesOfInterest)
		if err != nil {
			continue
		}
		ldapSuccess = true
		break
	}
	if !ldapSuccess {
		return nil, errors.New("could not contact any configured LDAP endpoint")
	}
	groupPrefixString := ""
	if groupPrefix != nil {
		groupPrefixString = *groupPrefix
	}
	uinfo.logger.Debugf(2, "userAttributes=%+v", userAttributes)
	groupsOfInterest, err := uinfo.extractCNFromDNString(userAttributes["memberOf"], groupPrefixString)
	if err != nil {
		return nil, err
	}
	return groupsOfInterest, nil
}
