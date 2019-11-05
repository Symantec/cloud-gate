package staticconfiguration

import (
	"time"
)

type BaseConfig struct {
	ServicePort                       uint16        `yaml:"service_port"`
	StatusPort                        uint16        `yaml:"status_port"`
	TLSCertFilename                   string        `yaml:"tls_cert_filename"`
	TLSKeyFilename                    string        `yaml:"tls_key_filename"`
	AWSCredentialsFilename            string        `yaml:"aws_credentials_filename"`
	AWSListRolesRoleName              string        `yaml:"aws_list_roles_role_name"`
	AccountConfigurationUrl           string        `yaml:"account_configuration_url"`
	AccountConfigurationCheckInterval time.Duration `yaml:"account_configuration_check_interval"`
	ClientCAFilename                  string        `yaml:"client_ca_filename"`
	DataDirectory                     string        `yaml:"data_directory"`
	SharedDataDirectory               string        `yaml:"shared_data_directory"`
	ClusterSharedSecretFilename       string        `yaml:"cluster_shared_secret_filename"`
	SharedSecrets                     []string
}

type GitDatabaseConfig struct {
	CheckInterval            time.Duration `yaml:"check_interval"`
	LocalRepositoryDirectory string        `yaml:"local_repository_directory"`
	RepositoryURL            string        `yaml:"repository_url"`
}

type OpenIDConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	ProviderURL  string `yaml:"provider_url"`
	AuthURL      string `yaml:"auth_url"`
	TokenURL     string `yaml:"token_url"`
	UserinfoURL  string `yaml:"userinfo_url"`
	Scopes       string `yaml:"scopes"`
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
	GitDB  GitDatabaseConfig
	OpenID OpenIDConfig
	Ldap   UserInfoLDAPSource
}
