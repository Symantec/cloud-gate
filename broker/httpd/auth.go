package httpd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	//"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func randomStringGeneration() (string, error) {
	const size = 32
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *Server) setAndStoreAuthCookie(w http.ResponseWriter, username string) error {
	randomString, err := randomStringGeneration()
	if err != nil {
		s.logger.Println(err)
		return err
	}
	expires := time.Now().Add(time.Hour * cookieExpirationHours)

	userCookie := http.Cookie{Name: authCookieName, Value: randomString, Path: "/", Expires: expires, HttpOnly: true, Secure: true}

	http.SetCookie(w, &userCookie)

	Cookieinfo := AuthCookie{username, userCookie.Expires}

	s.cookieMutex.Lock()
	s.authCookie[userCookie.Value] = Cookieinfo
	s.cookieMutex.Unlock()
	return nil
}

const maxAgeSecondsRedirCookie = 120
const redirCookieName = "oauth2_redir"
const oauth2redirectPath = "/oauth2/redirectendpoint"

type oauth2StateJWT struct {
	Issuer     string   `json:"iss,omitempty"`
	Subject    string   `json:"sub,omitempty"`
	Audience   []string `json:"aud,omitempty"`
	Expiration int64    `json:"exp,omitempty"`
	NotBefore  int64    `json:"nbf,omitempty"`
	IssuedAt   int64    `json:"iat,omitempty"`
	ReturnURL  string   `json:"return_url,omitempty"`
}

func (s *Server) getRedirURL(r *http.Request) string {
	return "https://" + r.Host + oauth2redirectPath
}

func (s *Server) generateAuthCodeURL(state string, r *http.Request) string {
	var buf bytes.Buffer
	buf.WriteString(s.staticConfig.OpenID.AuthURL)
	redirectURL := s.getRedirURL(r)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {s.staticConfig.OpenID.ClientID},
		"scope":         {s.staticConfig.OpenID.Scopes},
		"redirect_uri":  {redirectURL},
	}

	if state != "" {
		// TODO(light): Docs say never to omit state; don't allow empty.
		v.Set("state", state)
	}
	if strings.Contains(s.staticConfig.OpenID.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

func (s *Server) oauth2DoRedirectoToProviderHandler(w http.ResponseWriter, r *http.Request) {

	key := []byte(s.staticConfig.Base.SharedSecrets[0])
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		s.logger.Printf("err=%s", err)
		http.Error(w, "Internal Error ", http.StatusInternalServerError)
		return
	}
	issuer := "cloud-gate"
	subject := "state:" + redirCookieName
	stateToken := oauth2StateJWT{Issuer: issuer, Subject: subject,
		Audience:  []string{issuer},
		ReturnURL: r.URL.String()}
	stateToken.NotBefore = time.Now().Unix()
	stateToken.IssuedAt = stateToken.NotBefore
	stateToken.Expiration = stateToken.IssuedAt + maxAgeSecondsRedirCookie
	stateString, err := jwt.Signed(sig).Claims(stateToken).CompactSerialize()
	if err != nil {
		s.logger.Printf("err=%s", err)
		http.Error(w, "Internal Error ", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, s.generateAuthCodeURL(stateString, r), http.StatusFound)
}

func (s *Server) JWTClaims(t *jwt.JSONWebToken, dest ...interface{}) (err error) {
	for _, key := range s.staticConfig.Base.SharedSecrets {
		binkey := []byte(key)
		err = t.Claims(binkey, dest...)
		if err == nil {
			return nil
		}
	}
	if err != nil {
		return err
	}
	err = errors.New("No valid key found")
	return err
}

type accessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:expires_in`
	IDToken     string `json:"id_token"`
}

type openidConnectUserInfo struct {
	Subject           string `json:"sub"`
	Name              string `json:"name"`
	Login             string `json:"login,omitempty"`
	Username          string `json:"username,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
}

func getUsernameFromUserinfo(userInfo openidConnectUserInfo) string {
	username := userInfo.Username
	if len(username) < 1 {
		username = userInfo.Login
	}
	if len(username) < 1 {
		username = userInfo.PreferredUsername
	}
	if len(username) < 1 {
		username = userInfo.Email
	}
	return username
}

func (s *Server) oauth2RedirectPathHandler(w http.ResponseWriter, r *http.Request) {
	authCode := r.URL.Query().Get("code")
	if len(authCode) < 1 {
		s.logger.Println("null code")
		http.Error(w, "null code", http.StatusUnauthorized)
		return

	}

	serializedState := r.URL.Query().Get("state")
	if len(serializedState) < 1 {
		s.logger.Println("null inboundState")
		http.Error(w, "null inboundState", http.StatusUnauthorized)
		return
	}
	tok, err := jwt.ParseSigned(serializedState)
	if err != nil {
		//return rvalue, err
		s.logger.Printf("bad inboundState, error on parsing %s", err)
		http.Error(w, "bad inboundState", http.StatusUnauthorized)
		return
	}
	s.logger.Printf("tok=%+v", tok)
	inboundJWT := oauth2StateJWT{}
	if err := s.JWTClaims(tok, &inboundJWT); err != nil {
		s.logger.Printf("error parsing claims err=%s", err)
		//return rvalue, err
		http.Error(w, "bad inboundState", http.StatusUnauthorized)
		return
	}
	// At this point we know the signature is valid, but now we must
	//validate the contents of the jtw token
	issuer := "cloud-gate"
	subject := "state:" + redirCookieName
	if inboundJWT.Issuer != issuer || inboundJWT.Subject != subject ||
		inboundJWT.NotBefore > time.Now().Unix() || inboundJWT.Expiration < time.Now().Unix() {
		err = errors.New("invalid JWT values")
		http.Error(w, "bad inboundState", http.StatusUnauthorized)
		return
	}
	// OK state  is valid.. now we perform the token exchange
	redirectURL := s.getRedirURL(r)
	tokenResp, err := s.netClient.PostForm(s.staticConfig.OpenID.TokenURL,
		url.Values{"redirect_uri": {redirectURL},
			"code":          {authCode},
			"grant_type":    {"authorization_code"},
			"client_id":     {s.staticConfig.OpenID.ClientID},
			"client_secret": {s.staticConfig.OpenID.ClientSecret},
		})
	if err != nil {
		s.logger.Printf("err=%s", err)
		http.Error(w, "bad transaction with openic context ", http.StatusInternalServerError)
		return
	}
	defer tokenResp.Body.Close()

	tokenRespBody, err := ioutil.ReadAll(tokenResp.Body)
	if err != nil {
		s.logger.Printf("err=%s", err)
		http.Error(w, "bad transaction with openic context ", http.StatusInternalServerError)
		return
	}

	if tokenResp.StatusCode >= 300 {
		s.logger.Printf(string(tokenRespBody))
		http.Error(w, "bad transaction with openic context ", http.StatusInternalServerError)
		return
	}
	var oauth2AccessToken accessToken
	err = json.Unmarshal(tokenRespBody, &oauth2AccessToken)
	if err != nil {
		s.logger.Printf(string(tokenRespBody))
		http.Error(w, "cannot decode oath2 response for token ", http.StatusInternalServerError)
		return
	}
	// TODO: tolower
	if oauth2AccessToken.TokenType != "Bearer" || len(oauth2AccessToken.AccessToken) < 1 {
		s.logger.Printf(string(tokenRespBody))
		http.Error(w, "invalid accessToken ", http.StatusInternalServerError)
		return
	}

	// we could stop here if we check the signature, but lets keep going.
	userInfoResp, err := s.netClient.PostForm(s.staticConfig.OpenID.UserinfoURL,
		url.Values{"access_token": {oauth2AccessToken.AccessToken}})
	if err != nil {
		s.logger.Printf("err=%s", err)
		http.Error(w, "bad transaction with openic context ", http.StatusInternalServerError)
		return
	}
	defer userInfoResp.Body.Close()

	userInfoRespBody, err := ioutil.ReadAll(userInfoResp.Body)
	if err != nil {
		s.logger.Printf("err=%s", err)
		http.Error(w, "bad transaction with openic context ", http.StatusInternalServerError)
		return
	}

	if userInfoResp.StatusCode >= 300 {
		s.logger.Printf(string(tokenRespBody))
		http.Error(w, "bad transaction with openic context ", http.StatusInternalServerError)
		return
	}
	var userInfo openidConnectUserInfo
	err = json.Unmarshal(userInfoRespBody, &userInfo)
	if err != nil {
		s.logger.Printf(string(tokenRespBody))
		http.Error(w, "cannot decode oath2 userinfo token ", http.StatusInternalServerError)
		return
	}
	username := getUsernameFromUserinfo(userInfo)

	err = s.setAndStoreAuthCookie(w, username)
	if err != nil {
		s.logger.Println(err)
		http.Error(w, "cannot set auth Cookie", http.StatusInternalServerError)
		return
	}

	destinationPath := inboundJWT.ReturnURL

	http.Redirect(w, r, destinationPath, http.StatusFound)

}

func setupSecurityHeaders(w http.ResponseWriter) error {
	//all common security headers go here
	w.Header().Set("Strict-Transport-Security", "max-age=31536")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1")
	w.Header().Set("Content-Security-Policy", "default-src 'self' ;style-src 'self' maxcdn.bootstrapcdn.com fonts.googleapis.com 'unsafe-inline'; font-src maxcdn.bootstrapcdn.com fonts.gstatic.com fonts.googleapis.com")

	return nil
}

func (s *Server) GetRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {
	// If you have a verified cert, no need for cookies
	if r.TLS != nil {
		if len(r.TLS.VerifiedChains) > 0 {
			clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
			return clientName, nil
		}
	}

	_ = setupSecurityHeaders(w)

	remoteCookie, err := r.Cookie(authCookieName)
	if err != nil {
		s.logger.Println(err)
		s.oauth2DoRedirectoToProviderHandler(w, r)
		return "", err
	}
	s.cookieMutex.Lock()
	defer s.cookieMutex.Unlock()
	authInfo, ok := s.authCookie[remoteCookie.Value]

	if !ok {
		s.oauth2DoRedirectoToProviderHandler(w, r)
		return "", errors.New("Cookie not found")
	}
	if authInfo.ExpiresAt.Before(time.Now()) {
		s.oauth2DoRedirectoToProviderHandler(w, r)
		return "", errors.New("Expired Cookie")
	}
	return authInfo.Username, nil
}
