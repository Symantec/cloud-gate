package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	//"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/ini.v1"
)

var (
	certFilename         = flag.String("cert", filepath.Join(os.Getenv("HOME"), ".ssl", "keymaster.cert"), "A PEM eoncoded certificate file.")
	keyFilename          = flag.String("key", filepath.Join(os.Getenv("HOME"), ".ssl", "keymaster.key"), "A PEM encoded private key file.")
	baseURL              = flag.String("baseURL", "https://cloud-gate-dev.symcpe.net", "location of the cloud-broker")
	crededentialFilename = flag.String("credentialFile", filepath.Join(os.Getenv("HOME"), ".aws", "credentials"), "An Ini file with credentials")
	askAdminRoles        = flag.Bool("askAdminRoles", false, "ask also for admin roles")
	outputProfilePrefix  = flag.String("outputProfilePrefix", "saml-", "prefix to put to profile names $PREFIX$accountName-$roleName")
	lowerCaseProfileName = flag.Bool("lowerCaseProfileName", true, "ask also for admin roles")
)

type cloudAccountInfo struct {
	Name           string
	AvailableRoles []string
}

type getAccountInfo struct {
	AuthUsername  string
	CloudAccounts map[string]cloudAccountInfo
}

type AWSCredentialsJSON struct {
	SessionId    string `json:"sessionId"`
	SessionKey   string `json:"sessionKey"`
	SessionToken string `json:"sessionToken"`
	Region       string `json:"region,omitempty"`
}

const badReturnErrText = "bad return code"
const sleepDuration = 1800 * time.Second

func getAndUptateCreds(client *http.Client, baseUrl, accountName, roleName string,
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

	return nil
}

func getCerts(cert tls.Certificate, baseUrl string,
	credentialFilename string, askAdminRoles bool,
	outputProfilePrefix string, lowerCaseProfileName bool) error {

	// Create file if it does not exist
	if _, err := os.Stat(credentialFilename); os.IsNotExist(err) {
		file, err := os.OpenFile(credentialFilename, os.O_RDONLY|os.O_CREATE, 0660)
		if err != nil {
			return err
		}
		file.Close()
	}

	credFile, err := ini.Load(credentialFilename)
	if err != nil {
		return err
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// Do GET something
	resp, err := client.Get(baseUrl)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	//log.Println(string(data))

	var accountList getAccountInfo
	err = json.Unmarshal(data, &accountList)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%+v", accountList)

	for _, account := range accountList.CloudAccounts {
		for _, roleName := range account.AvailableRoles {
			adminRole, err := regexp.Match("(?i)admin", []byte(roleName))
			if adminRole && !askAdminRoles {
				continue
			}
			if err != nil {
				log.Fatalf("error on regexp=%s", err)
			}
			err = getAndUptateCreds(client, baseUrl,
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

func main() {
	flag.Parse()

	certNotAfter, err := getCertExpirationTime(*certFilename)
	if err != nil {
		log.Fatal(err)
	}

	for certNotAfter.After(time.Now()) {
		cert, err := tls.LoadX509KeyPair(*certFilename, *keyFilename)
		if err != nil {
			log.Fatal(err)
		}
		err = getCerts(cert, *baseURL, *crededentialFilename,
			*askAdminRoles, *outputProfilePrefix, *lowerCaseProfileName)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Credentials Successfully generated sleeping for (%s)", sleepDuration)

		time.Sleep(sleepDuration)
		certNotAfter, err = getCertExpirationTime(*certFilename)
		if err != nil {
			log.Fatal(err)
		}

	}

	log.Printf("done")
}
