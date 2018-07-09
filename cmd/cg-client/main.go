package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"io/ioutil"
	//"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

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

func getAndUptateCreds(client *http.Client, baseUrl, accountName, roleName string, credFile *ini.File) error {
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
	log.Println(string(data))

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

	return nil
}

func main() {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certFilename, *keyFilename)
	if err != nil {
		log.Fatal(err)
	}
	err = getCerts(cert, *baseURL, *crededentialFilename)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("done")
}
