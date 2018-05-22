package appconfiguration

/*
import (
	"golang.org/x/oauth2"
)
*/

type BaseConfig struct {
	ListenPort      int    `yaml:"listen_port"`
	TLSCertFilename string `yaml:"tls_cert_filename"`
	TLSKeyFilename  string `yaml:"tls_key_filename"`
}

type Oauth2Config struct {
	//Config                  *oauth2.Config
	ClientID                string `yaml:"client_id"`
	ClientSecret            string `yaml:"client_secret"`
	OIDCProviderMetadataUrl string `yaml:"oidc_metadata_url"`
	//TokenUrl     string `yaml:"token_url"`
	//AuthUrl      string `yaml:"auth_url"`
	//UserinfoUrl  string `yaml:"userinfo_url"`
	//Scopes       string `yaml:"scopes"`
}

type AppConfiguration struct {
	Base BaseConfig
	//	Oauth2 Oauth2Config
}
