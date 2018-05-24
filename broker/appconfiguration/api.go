package appconfiguration

type BaseConfig struct {
	ServicePort     uint16 `yaml:"service_port"`
	StatusPort      uint16 `yaml:"status_port"`
	TLSCertFilename string `yaml:"tls_cert_filename"`
	TLSKeyFilename  string `yaml:"tls_key_filename"`
}

type AppConfiguration struct {
	Base BaseConfig
}
