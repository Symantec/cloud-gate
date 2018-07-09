package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io/ioutil"
	//"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/ini.v1"
)

var (
	certFilename         = flag.String("cert", filepath.Join(os.Getenv("HOME"), ".ssl", "keymaster.cert"), "A PEM eoncoded certificate file.")
	keyFilename          = flag.String("key", filepath.Join(os.Getenv("HOME"), ".ssl", "keymaster.key"), "A PEM encoded private key file.")
	baseURL              = flag.String("baseURL", "https://mon-sre-dev.us-east-1.aws.symcpe.net:32443", "location of the cloud-broker")
	crededentialFilename = flag.String("credentialFile", filepath.Join(os.Getenv("HOME"), ".aws", "credentials"), "An Ini file with credentials")
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

func getAndUptateCreds(client *http.Client, baseUrl, accountName, roleName string, cfg *ini.File) error {
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
	//log.Println(string(data))

	var awsCreds AWSCredentialsJSON
	err = json.Unmarshal(data, &awsCreds)
	if err != nil {
		log.Fatal(err)
	}
	//log.Printf("%+v", awsCreds)
	fileProfile := accountName + "-" + roleName
	cfg.Section(fileProfile).Key("aws_access_key_id").SetValue(awsCreds.SessionId)
	cfg.Section(fileProfile).Key("aws_secret_access_key").SetValue(awsCreds.SessionKey)
	cfg.Section(fileProfile).Key("aws_session_token").SetValue(awsCreds.SessionToken)

	return nil
}

func getCerts(cert tls.Certificate, baseUrl string, credentialFilename string) error {

	//get credfile, TODO: make if ones does not exist
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
			if adminRole {
				continue
			}
			err = getAndUptateCreds(client, baseUrl, account.Name, roleName, credFile)
			if err != nil {
				log.Fatal(err)
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
		sleepDuration := 1200 * time.Second
		cert, err := tls.LoadX509KeyPair(*certFilename, *keyFilename)
		if err != nil {
			log.Fatal(err)
		}
		err = getCerts(cert, *baseURL, *crededentialFilename)
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
