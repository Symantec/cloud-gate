package staticconfiguration

import (
	"time"
)

type BaseConfig struct {
	ServicePort                       uint16        `yaml:"service_port"`
	StatusPort                        uint16        `yaml:"status_port"`
	TLSCertFilename                   string        `yaml:"tls_cert_filename"`
	TLSKeyFilename                    string        `yaml:"tls_key_filename"`
	AccountConfigurationUrl           string        `yaml:"account_configuration_url"`
	AccountConfigurationCheckInterval time.Duration `yaml:"account_configuration_check_interval"`
}

type OpenIDConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	ProviderURL  string `yaml:"provider_url"`
}

type UserInfoLDAPSource struct {
	BindUsername       string   `yaml:"bind_username"`
	BindPassword       string   `yaml:"bind_password"`
	LDAPTargetURLs     string   `yaml:"ldap_target_urls"`
	UserSearchBaseDNs  []string `yaml:"user_search_base_dns"`
	UserSearchFilter   string   `yaml:"user_search_filter"`
	GroupSearchBaseDNs []string `yaml:"group_search_base_dns"`
	GroupSearchFilter  string   `yaml:"group_search_filter"`
}

type StaticConfiguration struct {
	Base   BaseConfig
	OpenID OpenIDConfig
	Ldap   UserInfoLDAPSource
}
