package httpd

import (
	//"encoding/json"
	//"errors"
	"fmt"
	//"io/ioutil"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/Symantec/Dominator/lib/log/debuglogger"
	"github.com/Symantec/cloud-gate/broker/staticconfiguration"
	"github.com/Symantec/cloud-gate/lib/constants"
)

func TestOauth2RedirectHandlerSucccess(t *testing.T) {
	slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	logger := debuglogger.New(slogger)
	server := &Server{
		logger:       logger,
		staticConfig: &staticconfiguration.StaticConfiguration{},
	}
	server.authCookie = make(map[string]AuthCookie)
	server.staticConfig.Base.SharedSecrets = []string{"secret"}

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	stateString, err := server.generateValidStateString(req)
	if err != nil {
		t.Fatal(err)
	}
	v := url.Values{
		"state": {stateString},
		"code":  {"12345"},
	}
	redirReq, err := http.NewRequest("GET", "/?"+v.Encode(), nil)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "{\"access_token\": \"6789\", \"token_type\": \"Bearer\",\"username\":\"user\"}")
	}))
	defer ts.Close()
	server.netClient = ts.Client()
	server.staticConfig.OpenID.TokenURL = ts.URL
	server.staticConfig.OpenID.UserinfoURL = ts.URL

	rr := httptest.NewRecorder()
	server.oauth2RedirectPathHandler(rr, redirReq)
	if rr.Code != http.StatusFound {
		t.Fatal("Response should have been a redirect")
	}
	resp := rr.Result()
	//body, _ := ioutil.ReadAll(resp.Body)
	//t.Logf("body =%s", string(body))
	if resp.Header.Get("Location") != "/" {
		t.Fatal("Response should have been a redirect to /")
	}

}

func TestGetRemoteUserNameHandler(t *testing.T) {
	slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	logger := debuglogger.New(slogger)
	server := &Server{
		logger:       logger,
		staticConfig: &staticconfiguration.StaticConfiguration{},
	}
	server.authCookie = make(map[string]AuthCookie)
	server.staticConfig.Base.SharedSecrets = []string{"secret"}

	// Test with no cookies... inmediate redirect
	urlList := []string{"/", "/static/foo"}
	for _, url := range urlList {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = checkRequestHandlerCode(req, func(w http.ResponseWriter, r *http.Request) {
			_, err := server.getRemoteUserName(w, r)
			if err == nil {
				t.Fatal("getRemoteUsername should have failed")
			}
		}, http.StatusFound)
		if err != nil {
			t.Fatal(err)
		}

	}
	// Now fail with an unknown cookie
	uknownCookieReq, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	cookieVal, err := randomStringGeneration()
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: constants.AuthCookieName, Value: cookieVal}
	uknownCookieReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(uknownCookieReq, func(w http.ResponseWriter, r *http.Request) {
		_, err := server.getRemoteUserName(w, r)
		if err == nil {
			t.Fatal("getRemoteUsername should have failed")
		}
	}, http.StatusFound)

}
