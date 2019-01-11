package constants

import (
	"time"
)

const (
	DefaultServicePort                       = 443
	DefaultStatusPort                        = 6930
	DefaultAccountConfigurationUrl           = "file:///etc/cloud-gate/accounts.yml"
	DefaultAccountConfigurationCheckInterval = time.Minute * 5

	SecondsBetweenCleanup    = 60
	LoginPath                = "/login/"
	OidcCallbackPath         = "/auth/oidcsimple/callback"
	CookieExpirationHours    = 3
	AuthCookieName           = "auth_cookie"
	Oauth2redirectPath       = "/oauth2/redirectendpoint"
	RedirCookieName          = "oauth2_redir"
	MaxAgeSecondsRedirCookie = 120
)
