package ldap

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Symantec/Dominator/lib/log"
	"github.com/Symantec/keymaster/lib/authutil"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	dependencyLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "cloudgate_ldap_userinfo_check_duration_seconds",
			Help:       "LDAP Dependency latency",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"target"},
	)
	userinfoLDAPAttempt = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cloudgate_ldap_userinfo_attempt_counter",
			Help: "Attempts to get userinfo from ldap",
		},
	)
	userinfoLDAPSuccess = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cloudgate_ldap_userinfo_success_counter",
			Help: "Success count when getting userinfo from ldap",
		},
	)
)

func init() {
	prometheus.MustRegister(dependencyLatency)
	prometheus.MustRegister(userinfoLDAPAttempt)
	prometheus.MustRegister(userinfoLDAPSuccess)
}

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
	userinfoLDAPAttempt.Inc()
	for _, ldapUrl := range uinfo.ldapURL {
		targetName := strings.ToLower(ldapUrl.Hostname())
		startTime := time.Now()
		userAttributes, err = authutil.GetLDAPUserAttributes(*ldapUrl, uinfo.bindUsername, uinfo.bindPassword,
			uinfo.timeoutSecs, uinfo.rootCAs,
			username,
			uinfo.userSearchBaseDNs, uinfo.userSearchFilter,
			attributesOfInterest)
		if err != nil {
			continue
		}
		dependencyLatency.WithLabelValues(targetName).Observe(time.Now().Sub(startTime).Seconds())
		ldapSuccess = true
		break
	}
	if !ldapSuccess {
		return nil, fmt.Errorf("Could not contact any configured LDAP endpoint. Last Err: %s", err)
	}
	userinfoLDAPSuccess.Inc()
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
