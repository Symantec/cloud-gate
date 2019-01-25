package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v2"
)

var (
	// Must be a global variable in the data segment so that the build
	// process can inject the version number on the fly when building the
	// binary. Use only from the Usage() function.
	Version        = "No version provided"
	DefaultBaseURL = ""
)

const defaultOutputProfilePrefix = "saml-"

var (
	certFilename         = flag.String("cert", filepath.Join(getUserHomeDir(), ".ssl", "keymaster.cert"), "A PEM eoncoded certificate file.")
	keyFilename          = flag.String("key", filepath.Join(getUserHomeDir(), ".ssl", "keymaster.key"), "A PEM encoded private key file.")
	baseURL              = flag.String("baseURL", "", "location of the cloud-broker")
	crededentialFilename = flag.String("credentialFile", filepath.Join(getUserHomeDir(), ".aws", "credentials"), "An Ini file with credentials")
	askAdminRoles        = flag.Bool("askAdminRoles", false, "ask also for admin roles")
	outputProfilePrefix  = flag.String("outputProfilePrefix", defaultOutputProfilePrefix, "prefix to put to profile names $PREFIX$accountName-$roleName")
	lowerCaseProfileName = flag.Bool("lowerCaseProfileName", true, "ask also for admin roles")
	configFilename       = flag.String("configFile", filepath.Join(getUserHomeDir(), ".config", "cloud-gate", "config.yml"), "An Ini file with credentials")
	oldBotoCompat        = flag.Bool("oldBotoCompat", false, "add aws_security_token for OLD boto installations (not recommended)")
)

type AppConfigFile struct {
	BaseURL              string `yaml:"base_url"`
	OutputProfilePrefix  string `yaml:"output_profile_prefix"`
	LowerCaseProfileName bool   `yaml:"lower_case_profile_name"`
}

type cloudAccountInfo struct {
	Name           string
	AvailableRoles []string
}

type getAccountInfo struct {
	AuthUsername  string
	CloudAccounts map[string]cloudAccountInfo
}

type AWSCredentialsJSON struct {
	SessionId    string    `json:"sessionId"`
	SessionKey   string    `json:"sessionKey"`
	SessionToken string    `json:"sessionToken"`
	Region       string    `json:"region,omitempty"`
	Expiration   time.Time `json:"cloudgate_comment_expiration,omitempty"`
}

func loadVerifyConfigFile(filename string) (AppConfigFile, error) {
	var config AppConfigFile
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		err = saveDefaultConfig(filename)
		if err != nil {
			return config, err
		}
	}
	source, err := ioutil.ReadFile(filename)
	if err != nil {
		err = errors.New("cannot read config file")
		return config, err
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		err = errors.New("Cannot parse config file")
		return config, err
	}

	if len(config.BaseURL) < 1 {
		err = errors.New("Invalid Config file... no place get the credentials")
		return config, err
	}
	// TODO: ensure all enpoints are https urls
	return config, nil
}

func saveDefaultConfig(configFilename string) error {
	os.MkdirAll(filepath.Dir(configFilename), 0755)
	config := AppConfigFile{
		BaseURL:              DefaultBaseURL,
		OutputProfilePrefix:  defaultOutputProfilePrefix,
		LowerCaseProfileName: true,
	}
	configBytes, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configFilename, configBytes, 0644)

}

const badReturnErrText = "bad return code"
const sleepDuration = 1800 * time.Second
const failureSleepDuration = 60 * time.Second

func getAndUpdateCreds(client *http.Client, baseUrl, accountName, roleName string,
	cfg *ini.File, outputProfilePrefix string,
	lowerCaseProfileName bool) error {
	log.Printf("account=%s, role=%s", accountName, roleName)

	resp, err := client.PostForm(baseUrl+"/generatetoken",
		url.Values{"accountName": {accountName}, "roleName": {roleName}})
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode >= 300 {
		return errors.New(badReturnErrText)
	}
	//log.Println(string(data))

	var awsCreds AWSCredentialsJSON
	err = json.Unmarshal(data, &awsCreds)
	if err != nil {
		log.Fatal(err)
	}
	//log.Printf("%+v", awsCreds)
	fileProfile := outputProfilePrefix + accountName + "-" + roleName
	if lowerCaseProfileName {
		fileProfile = strings.ToLower(fileProfile)
	}
	cfg.Section(fileProfile).Key("aws_access_key_id").SetValue(awsCreds.SessionId)
	cfg.Section(fileProfile).Key("aws_secret_access_key").SetValue(awsCreds.SessionKey)
	cfg.Section(fileProfile).Key("aws_session_token").SetValue(awsCreds.SessionToken)
	if *oldBotoCompat {
		cfg.Section(fileProfile).Key("aws_security_token").SetValue(awsCreds.SessionToken)
	} else {
		cfg.Section(fileProfile).DeleteKey("aws_security_token")
	}
	if !awsCreds.Expiration.IsZero() {
		cfg.Section(fileProfile).Key("token_expiration").SetValue(awsCreds.Expiration.UTC().Format(time.RFC3339))
	} else {
		cfg.Section(fileProfile).DeleteKey("token_expiration")
	}

	return nil
}

func getParseURLEnvVariable(name string) (*url.URL, error) {
	envVariable := os.Getenv(name)
	if len(envVariable) < 1 {
		return nil, nil
	}
	envURL, err := url.Parse(envVariable)
	if err != nil {
		return nil, err
	}

	return envURL, nil
}

func setupCredentialFile(credentialFilename string) (*ini.File, error) {
	// Create file if it does not exist
	if _, err := os.Stat(credentialFilename); os.IsNotExist(err) {
		os.MkdirAll(filepath.Dir(credentialFilename), 0770)
		file, err := os.OpenFile(credentialFilename, os.O_RDONLY|os.O_CREATE, 0660)
		if err != nil {
			return nil, err
		}
		file.Close()
	}

	return ini.Load(credentialFilename)
}

func setupHttpClient(cert tls.Certificate) (*http.Client, error) {
	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}

	// proxy env variables in ascending order of preference, lower case 'http_proxy' dominates
	// just like curl
	proxyEnvVariables := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy"}
	for _, proxyVar := range proxyEnvVariables {
		httpProxy, err := getParseURLEnvVariable(proxyVar)
		if err == nil && httpProxy != nil {
			transport.Proxy = http.ProxyURL(httpProxy)
		}
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	return client, nil
}

func getAccountsList(client *http.Client, baseUrl string) (*getAccountInfo, error) {
	// Do GET something
	resp, err := client.Get(baseUrl)
	if err != nil {
		log.Printf("failed to connect err=%s transport=%+v ", err, client.Transport)
		if resp != nil {
			log.Printf("resp=+%v", resp)
		}
		return nil, err
	}
	defer resp.Body.Close()

	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var accountList getAccountInfo
	err = json.Unmarshal(data, &accountList)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%+v", accountList)
	return &accountList, nil

}

func getCerts(cert tls.Certificate, baseUrl string,
	credentialFilename string, askAdminRoles bool,
	outputProfilePrefix string, lowerCaseProfileName bool) error {

	credFile, err := setupCredentialFile(credentialFilename)
	if err != nil {
		return err
	}

	client, err := setupHttpClient(cert)
	if err != nil {
		return err
	}
	accountList, err := getAccountsList(client, baseUrl)
	if err != nil {
		return err
	}

	for _, account := range accountList.CloudAccounts {
		for _, roleName := range account.AvailableRoles {
			adminRole, err := regexp.Match("(?i)admin", []byte(roleName))
			if adminRole && !askAdminRoles {
				continue
			}
			if err != nil {
				log.Fatalf("error on regexp=%s", err)
			}
			err = getAndUpdateCreds(client, baseUrl,
				account.Name, roleName, credFile,
				outputProfilePrefix, lowerCaseProfileName)
			if err != nil {
				if err.Error() == badReturnErrText {
					log.Printf("skipping role")
					continue
				}
				log.Fatalf("error on getAnd UpdateCreds=%s", err)
			}
		}
	}
	err = credFile.SaveTo(credentialFilename)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

//Assumes cert is pem ecoded
func getCertExpirationTime(certFilename string) (time.Time, error) {
	dat, err := ioutil.ReadFile(certFilename)
	if err != nil {
		return time.Now(), err
	}
	block, _ := pem.Decode(dat)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Now(), err
	}
	return cert.NotAfter, nil
}

func getUserHomeDir() (homeDir string) {
	homeDir = os.Getenv("HOME")
	if homeDir != "" {
		return homeDir
	}
	usr, err := user.Current()
	if err != nil {
		return homeDir
	}
	// TODO: verify on Windows... see: http://stackoverflow.com/questions/7922270/obtain-users-home-directory
	homeDir = usr.HomeDir
	return
}

func usage() {
	fmt.Fprintf(
		os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()

	config, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		log.Fatal(err)
	}
	if *outputProfilePrefix != defaultOutputProfilePrefix {
		config.OutputProfilePrefix = *outputProfilePrefix
	}
	if *baseURL != "" {
		config.BaseURL = *baseURL
	}

	log.Printf("Configuration Loaded")
	certNotAfter, err := getCertExpirationTime(*certFilename)
	if err != nil {
		log.Fatal(err)
	}
	if certNotAfter.Before(time.Now()) {
		log.Fatalf("keymaster certificate is expired, please run keymaster binary. Certificate expired at %s", certNotAfter)
	}

	for certNotAfter.After(time.Now()) {
		cert, err := tls.LoadX509KeyPair(*certFilename, *keyFilename)
		if err != nil {
			log.Fatal(err)
		}
		err = getCerts(cert, config.BaseURL, *crededentialFilename,
			*askAdminRoles, config.OutputProfilePrefix, *lowerCaseProfileName)
		if err != nil {
			log.Printf("err=%s", err)
			log.Printf("Failure getting certs, retrying in (%s)", failureSleepDuration)
			time.Sleep(failureSleepDuration)
		} else {
			log.Printf("Credentials Successfully generated sleeping for (%s)", sleepDuration)
			time.Sleep(sleepDuration)
		}
		certNotAfter, err = getCertExpirationTime(*certFilename)
		if err != nil {
			log.Fatal(err)
		}

	}

	log.Printf("done")
}
