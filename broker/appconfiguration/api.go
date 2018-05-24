package appconfiguration

type BaseConfig struct {
	ServicePort     uint16 `yaml:"service_port"`
	StatusPort      uint16 `yaml:"status_port"`
	TLSCertFilename string `yaml:"tls_cert_filename"`
	TLSKeyFilename  string `yaml:"tls_key_filename"`
}

type OpenIDConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	ProviderURL  string `yaml:"provider_url"`
}

type AppConfiguration struct {
	Base   BaseConfig
	OpenID OpenIDConfig
}
