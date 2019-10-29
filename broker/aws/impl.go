package aws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/Symantec/cloud-gate/broker"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"

	"gopkg.in/ini.v1"
)

// TODO: these should come in from config
const masterAWSProfileName = "broker-master"

func (b *Broker) accountIDFromName(accountName string) (string, error) {
	for _, account := range b.config.AWS.Account {
		if account.Name == accountName {
			return account.AccountID, nil
		}
	}
	return "", errors.New("accountNAme not found")
}

func (b *Broker) accountHumanNameFromName(accountName string) (string, error) {
	for _, account := range b.config.AWS.Account {
		if account.Name == accountName {
			if account.DisplayName != "" {
				return account.DisplayName, nil
			}
			return account.Name, nil
		}
	}
	return "", errors.New("accountNAme not found")
}

func (b *Broker) processNewUnsealingSecret(secret string) (ready bool, err error) {
	// if already loaded then fast quit
	//probably add some mutex here
	if len(b.profileCredentials) > 0 {
		return true, nil
	}

	decbuf := bytes.NewBuffer(b.rawCredentialsFile)

	armorBlock, err := armor.Decode(decbuf)
	if err != nil {
		b.logger.Printf("Cannot decode armored file")
		return false, err
	}
	password := []byte(secret)
	failed := false
	prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		// If the given passphrase isn't correct, the function will be called again, forever.
		// This method will fail fast.
		// Ref: https://godoc.org/golang.org/x/crypto/openpgp#PromptFunction
		if failed {
			return nil, errors.New("decryption failed")
		}
		failed = true
		return password, nil
	}
	md, err := openpgp.ReadMessage(armorBlock.Body, nil, prompt, nil)
	if err != nil {
		b.logger.Printf("cannot read message")
		return false, err
	}

	plaintextBytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return false, err
	}

	err = b.loadCredentialsFrombytes(plaintextBytes)
	if err != nil {
		return false, nil
	}

	return true, nil
}

func (b *Broker) loadCredentialsFile() (err error) {
	b.rawCredentialsFile, err = ioutil.ReadFile(b.credentialsFilename)
	if err != nil {
		return nil
	}
	fileAsString := string(b.rawCredentialsFile[:])
	if strings.HasPrefix(fileAsString, "-----BEGIN PGP MESSAGE-----") {
		return nil
	}
	return b.loadCredentialsFrombytes(b.rawCredentialsFile)
}

func (b *Broker) loadCredentialsFrombytes(credentials []byte) error {
	cfg, err := ini.Load(credentials)
	if err != nil {
		return err
	}
	defaultRegion := "us-west-2"
	sections := cfg.SectionStrings()
	for _, profileName := range sections {
		accessKeyID := cfg.Section(profileName).Key("aws_access_key_id").String()
		secretAccessKey := cfg.Section(profileName).Key("aws_secret_access_key").String()
		if len(accessKeyID) < 3 || len(secretAccessKey) < 3 {
			continue
		}
		region := cfg.Section(profileName).Key("region").String()
		if region == "" {
			region = defaultRegion
		}

		entry := awsProfileEntry{AccessKeyID: accessKeyID,
			SecretAccessKey: secretAccessKey,
			Region:          region}

		b.profileCredentials[profileName] = entry

	}
	if len(b.profileCredentials) < 1 {
		return errors.New("nothing loaded")
	}
	//it is now unsealed
	b.isUnsealedChannel <- nil
	return nil
}

// Returns a aws static credentials and region name, returns nil if credentials cannot be found
func (b *Broker) getCredentialsFromProfile(profileName string) (*credentials.Credentials, string, error) {
	profileEntry, ok := b.profileCredentials[profileName]
	if !ok {
		return nil, "", errors.New("invalid credentials name")
	}
	sessionCredentials := credentials.NewStaticCredentials(profileEntry.AccessKeyID, profileEntry.SecretAccessKey, "")
	return sessionCredentials, profileEntry.Region, nil
}

const profileAssumeRoleDurationSeconds = 3600

func (b *Broker) withProfileAssumeRole(accountName string, profileName string, roleName string, roleSessionName string) (*sts.AssumeRoleOutput, string, error) {
	sessionCredentials, region, err := b.getCredentialsFromProfile(profileName)
	if err != nil {
		return nil, "", err
	}
	if sessionCredentials == nil {
		return nil, "", fmt.Errorf("No valid profile=%s", profileName)
	}

	// This is strange, no error calling?
	masterSession := session.Must(session.NewSession(aws.NewConfig().WithCredentials(sessionCredentials).WithRegion(region)))
	stsClient := sts.New(masterSession)

	b.logger.Debugf(2, "stsClient=%v", stsClient)

	var durationSeconds int64
	durationSeconds = profileAssumeRoleDurationSeconds
	accountID, err := b.accountIDFromName(accountName)
	if err != nil {
		return nil, "", err
	}

	arnRolePrefix := "arn:aws:iam"
	if strings.HasPrefix(region, "us-gov-") {
		arnRolePrefix = "arn:aws-us-gov:iam"
	}
	roleArn := fmt.Sprintf("%s::%s:role/%s", arnRolePrefix, accountID, roleName)

	assumeRoleInput := sts.AssumeRoleInput{
		DurationSeconds: &durationSeconds,
		RoleArn:         &roleArn,
		RoleSessionName: &roleSessionName,
	}
	assumeRoleOutput, err := stsClient.AssumeRole(&assumeRoleInput)
	return assumeRoleOutput, region, err
}

func (b *Broker) withSessionGetAWSRoleList(validSession *session.Session) ([]string, error) {
	iamClient := iam.New(validSession)
	var maxItems int64
	maxItems = 500
	listRolesInput := iam.ListRolesInput{MaxItems: &maxItems}

	var roleNames []string
	err := iamClient.ListRolesPages(&listRolesInput,
		func(listRolesOutput *iam.ListRolesOutput, lastPage bool) bool {
			b.logger.Debugf(2, "listrolesoutput =%v", listRolesOutput)
			b.logger.Debugf(2, "loop, lastPage=%s", lastPage)
			for _, role := range listRolesOutput.Roles {
				roleNames = append(roleNames, *role.RoleName)
			}
			return !lastPage
		})
	if err != nil {
		return nil, err
	}
	sort.Strings(roleNames)
	b.logger.Debugf(1, "roleNames(v =%v)", roleNames)
	return roleNames, nil
}

func (b *Broker) masterGetAWSRolesForAccount(accountName string) ([]string, error) {
	assumeRoleOutput, region, err := b.withProfileAssumeRole(accountName, masterAWSProfileName, b.masterRoleName, "brokermaster")
	if err != nil {
		b.logger.Debugf(0, "cannot assume master role for account %s, err=%s", accountName, err)
		return nil, err
	}
	b.logger.Debugf(2, "assume role success for account=%s, roleoutput=%v", accountName, assumeRoleOutput)

	sessionCredentials := credentials.NewStaticCredentials(*assumeRoleOutput.Credentials.AccessKeyId,
		*assumeRoleOutput.Credentials.SecretAccessKey, *assumeRoleOutput.Credentials.SessionToken)
	assumedSession := session.Must(session.NewSession(aws.NewConfig().WithCredentials(sessionCredentials).WithRegion(region)))

	return b.withSessionGetAWSRoleList(assumedSession)
}

func (b *Broker) getAWSRolesForAccountNonCached(accountName string) ([]string, error) {
	b.logger.Debugf(1, "top of getAWSRolesForAccount for account =%s", accountName)
	accountRoles, err := b.masterGetAWSRolesForAccount(accountName)
	if err == nil {
		return accountRoles, nil
	}
	b.logger.Printf("Doing fallback for accountName=%s", accountName)
	// Master role does not work, try fallback with direct account
	profileName := accountName
	sessionCredentials, region, err := b.getCredentialsFromProfile(profileName)
	if err != nil {
		return nil, err
	}

	if sessionCredentials == nil {
		return nil, errors.New(fmt.Sprintf("no valid profile=%s", profileName))
	}

	// This is strange, no error calling?
	accountSession := session.Must(session.NewSession(aws.NewConfig().WithCredentials(sessionCredentials).WithRegion(region)))
	return b.withSessionGetAWSRoleList(accountSession)
}

const roleCacheDuration = time.Second * 1800

func (b *Broker) getAWSRolesForAccount(accountName string) ([]string, error) {
	b.accountRoleMutex.Lock()
	cachedEntry, ok := b.accountRoleCache[accountName]
	b.accountRoleMutex.Unlock()
	if ok {

		if cachedEntry.Expiration.After(time.Now()) {
			b.logger.Debugf(1, "Got roles from cache")
			return cachedEntry.Roles, nil
		}

		// Entry has expired
		value, err := b.getAWSRolesForAccountNonCached(accountName)
		if err != nil {
			// For availability reasons, we prefer to allow users to
			// continue using the cloudgate-server on expired AWS data
			// This allow us to continue to operate on transient AWS
			// errors.
			b.logger.Printf("Failure gettting non-cached roles, using expired cache")
			return cachedEntry.Roles, nil
		}
		cachedEntry.Roles = value
		cachedEntry.Expiration = time.Now().Add(roleCacheDuration)
		b.accountRoleMutex.Lock()
		b.accountRoleCache[accountName] = cachedEntry
		b.accountRoleMutex.Unlock()
		return value, nil
	}
	value, err := b.getAWSRolesForAccountNonCached(accountName)
	if err != nil {
		return value, err
	}
	cachedEntry.Roles = value
	cachedEntry.Expiration = time.Now().Add(roleCacheDuration)
	b.accountRoleMutex.Lock()
	b.accountRoleCache[accountName] = cachedEntry
	b.accountRoleMutex.Unlock()
	return value, nil
}

func stringIntersectionNoDups(set1, set2 []string) (intersection []string) {
	stringMap := make(map[string]string, len(set1))
	for _, v1 := range set1 {
		stringMap[strings.ToLower(v1)] = v1
	}
	for _, v2 := range set2 {
		v1, ok := stringMap[strings.ToLower(v2)]
		if ok {
			intersection = append(intersection, v1)
		}
	}
	return intersection
}

func (b *Broker) getUserAllowedAccountsFromGroups(userGroups []string) ([]broker.PermittedAccount, error) {
	var groupToAccountName map[string]string
	groupToAccountName = make(map[string]string)
	var groupList []string
	for _, account := range b.config.AWS.Account {
		groupName := account.GroupName
		if len(groupName) == 0 {
			groupName = account.Name
		}
		groupName = strings.ToLower(groupName)

		groupToAccountName[groupName] = account.Name
		groupList = append(groupList, groupName)
	}
	var allowedRoles map[string][]string
	allowedRoles = make(map[string][]string)

	for _, accountName := range groupList {
		reString := fmt.Sprintf("(?i)^%s-(.*)$", accountName)
		b.logger.Debugf(2, "reString=%v", reString)
		re, err := regexp.Compile(reString)
		if err != nil {
			return nil, err
		}
		for _, group := range userGroups {
			matches := re.FindStringSubmatch(group)
			b.logger.Debugf(4, "matches-XXX=%v %d", matches, len(matches))
			if len(matches) == 2 {
				b.logger.Debugf(2, "matches=%v", matches)
				accountGroupName := accountName
				allowedRoles[accountGroupName] = append(allowedRoles[accountGroupName], matches[1])
			}
		}
	}
	b.logger.Debugf(1, "allowedRoles(pre)=%v", allowedRoles)
	//now add extra roles:
	for _, account := range b.config.AWS.Account {
		if len(account.ExtraUserRoles) < 1 {
			continue
		}
		if currentValue, ok := allowedRoles[account.Name]; ok {
			allowedRoles[account.Name] = append(currentValue, account.ExtraUserRoles...)
		} else {
			allowedRoles[account.Name] = account.ExtraUserRoles
		}
	}
	b.logger.Debugf(1, "allowedRoles(post)=%v", allowedRoles)

	var permittedAccounts []broker.PermittedAccount
	for groupName, allowedRoles := range allowedRoles {
		accountName, ok := groupToAccountName[groupName]
		if !ok {
			return nil, errors.New("Cannot map to accountname for some username")
		}
		rolesForAccount, err := b.getAWSRolesForAccount(accountName)
		if err != nil {
			b.logger.Printf("Error getting profile for account %s: %s", accountName, err)
			continue
		}
		allowedAndAvailable := stringIntersectionNoDups(rolesForAccount, allowedRoles)
		if len(allowedAndAvailable) < 1 {
			continue
		}
		sort.Strings(allowedAndAvailable)

		displayName, err := b.accountHumanNameFromName(accountName)
		if err != nil {
			return nil, err
		}

		var account = broker.PermittedAccount{Name: accountName,
			HumanName:         displayName,
			PermittedRoleName: allowedAndAvailable}
		permittedAccounts = append(permittedAccounts, account)
	}
	b.logger.Debugf(1, "permittedAccounts=%+v", permittedAccounts)
	return permittedAccounts, nil
}

func (b *Broker) getUserAllowedAccountsNonCached(username string) ([]broker.PermittedAccount, error) {
	if b.config == nil {
		return nil, errors.New("nil config")
	}
	prefix := b.config.AWS.GroupPrefix
	userGroups, err := b.userInfo.GetUserGroups(username, &prefix)
	if err != nil {
		return nil, err
	}
	b.logger.Debugf(1, "UserGroups for '%s' =%+v", username, userGroups)

	return b.getUserAllowedAccountsFromGroups(userGroups)
}

const cacheDuration = time.Second * 300

func (b *Broker) getUserAllowedAccounts(username string) ([]broker.PermittedAccount, error) {
	b.userAllowedCredentialsMutex.Lock()
	cachedEntry, ok := b.userAllowedCredentialsCache[username]
	b.userAllowedCredentialsMutex.Unlock()
	if ok {
		if cachedEntry.Expiration.After(time.Now()) {
			b.logger.Debugf(1, "Got authz from cache")
			return cachedEntry.PermittedAccounts, nil
		}
		// entry is expired
		value, err := b.getUserAllowedAccountsNonCached(username)
		if err != nil {
			b.logger.Printf("Failure gettting non-cached, using expired cache")
			return cachedEntry.PermittedAccounts, nil
		}
		cachedEntry.PermittedAccounts = value
		cachedEntry.Expiration = time.Now().Add(cacheDuration)
		b.userAllowedCredentialsMutex.Lock()
		b.userAllowedCredentialsCache[username] = cachedEntry
		b.userAllowedCredentialsMutex.Unlock()
		return value, nil
	}
	value, err := b.getUserAllowedAccountsNonCached(username)
	if err != nil {
		b.logger.Printf("getUserAllowedAccounts: Failure gettting userinfo for non-cached user: %s. Err: %s", username, err)
		return value, err
	}
	cachedEntry.PermittedAccounts = value
	cachedEntry.Expiration = time.Now().Add(cacheDuration)
	b.userAllowedCredentialsMutex.Lock()
	b.userAllowedCredentialsCache[username] = cachedEntry
	b.userAllowedCredentialsMutex.Unlock()
	return value, nil
}

func (b *Broker) isUserAllowedToAssumeRole(username string, accountName string, roleName string) (bool, error) {
	// TODO: could be made more efficient, dont need to know all accounts, just one account.
	permittedAccount, err := b.getUserAllowedAccounts(username)
	if err != nil {
		return false, err
	}
	for _, account := range permittedAccount {
		if account.Name != accountName {
			continue
		}
		for _, permittedRoleName := range account.PermittedRoleName {
			if permittedRoleName == roleName {
				return true, nil
			}
		}
	}
	return false, nil
}

type ExchangeCredentialsJSON struct {
	SessionId    string `json:"sessionId"`
	SessionKey   string `json:"sessionKey"`
	SessionToken string `json:"sessionToken"`
}

type SessionTokenResponseJSON struct {
	SigninToken string `json:"SigninToken"`
}

const consoleSessionDurationSeconds = "43000" //3600 * 12

func (b *Broker) getConsoleURLForAccountRole(accountName string, roleName string, userName string, issuerURL string) (string, error) {
	assumeRoleOutput, region, err := b.withProfileAssumeRole(accountName, masterAWSProfileName, roleName, userName)
	if err != nil {
		b.logger.Debugf(1, "cannot assume role for account %s with master account, err=%s ", accountName, err)
		// try using a direct role if possible then
		assumeRoleOutput, region, err = b.withProfileAssumeRole(accountName, accountName, roleName, userName)
		if err != nil {
			b.logger.Printf("cannot assume role for account %s, err=%s", accountName, err)
			return "", err
		}
	}
	b.logger.Debugf(2, "assume role success for account=%s, roleoutput=%v", accountName, assumeRoleOutput)

	sessionCredentials := ExchangeCredentialsJSON{
		SessionId:    *assumeRoleOutput.Credentials.AccessKeyId,
		SessionKey:   *assumeRoleOutput.Credentials.SecretAccessKey,
		SessionToken: *assumeRoleOutput.Credentials.SessionToken,
	}
	b.logger.Debugf(2, "sessionCredentials=%v", sessionCredentials)

	bcreds, err := json.Marshal(sessionCredentials)
	if err != nil {
		return "", err
	}
	creds := url.QueryEscape(string(bcreds[:]))
	b.logger.Debugf(1, "sessionCredentials-escaped=%v", creds)

	federationUrl := "https://signin.aws.amazon.com/federation"
	awsDestinationURL := "https://console.aws.amazon.com/"
	if strings.HasPrefix(region, "us-gov-") {
		federationUrl = "https://signin.amazonaws-us-gov.com/federation"
		awsDestinationURL = "https://console.amazonaws-us-gov.com/"
	}

	req, err := http.NewRequest("GET", federationUrl, nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(bcreds[:]))
	q.Add("SessionDuration", consoleSessionDurationSeconds)
	req.URL.RawQuery = q.Encode()
	b.logger.Debugf(2, "req=%+v", req)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b.logger.Debugf(2, "resp=%+v", resp)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf(string(body))
	}
	b.logger.Debugf(1, "resp=%s", string(body))

	var tokenOutput SessionTokenResponseJSON
	err = json.Unmarshal(body, &tokenOutput)
	if err != nil {
		return "", err
	}
	b.logger.Debugf(1, "Issuer=%s", issuerURL)
	encodedIssuer := url.QueryEscape(issuerURL)
	targetUrl := fmt.Sprintf("%s?Action=login&Issuer=%s&Destination=%s&SigninToken=%s", federationUrl, encodedIssuer, awsDestinationURL, tokenOutput.SigninToken)
	b.logger.Debugf(1, "targetURL=%s", targetUrl)

	b.auditLogger.Printf("Console url generated for: %s on account %s role %s", userName, accountName, roleName)
	return targetUrl, nil
}

func (b *Broker) generateTokenCredentials(accountName string, roleName string, userName string) (*broker.AWSCredentialsJSON, error) {
	assumeRoleOutput, region, err := b.withProfileAssumeRole(accountName, masterAWSProfileName, roleName, userName)
	if err != nil {
		b.logger.Debugf(1, "cannot assume role for account %s with master account, err=%s ", accountName, err)
		// try using a direct role if possible then
		assumeRoleOutput, region, err = b.withProfileAssumeRole(accountName, accountName, roleName, userName)
		if err != nil {
			b.logger.Printf("cannot assume role for account %s, err=%s", accountName, err)
			return nil, err
		}
	}
	b.logger.Debugf(2, "assume role success for account=%s, roleoutput=%v", accountName, assumeRoleOutput)
	if !strings.HasPrefix(region, "us-gov-") {
		region = ""
	}
	outVal := broker.AWSCredentialsJSON{
		SessionId:    *assumeRoleOutput.Credentials.AccessKeyId,
		SessionKey:   *assumeRoleOutput.Credentials.SecretAccessKey,
		SessionToken: *assumeRoleOutput.Credentials.SessionToken,
		Region:       region,
		Expiration:   time.Now().Add(time.Second * profileAssumeRoleDurationSeconds),
	}
	b.auditLogger.Printf("Token credentials generated for: %s on account %s role %s", userName, accountName, roleName)
	return &outVal, nil
}
