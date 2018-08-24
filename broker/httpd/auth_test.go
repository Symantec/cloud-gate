package httpd

import (
	stdlog "log"
	"net/http"
	"os"
	"testing"

	"github.com/Symantec/Dominator/lib/log/debuglogger"
	"github.com/Symantec/cloud-gate/lib/constants"
)

func testgetRemoteUserNameWrapper(w http.ResponseWriter, r *http.Request) {
}

func TestGetRemoteUserNameHandler(t *testing.T) {
	slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	logger := debuglogger.New(slogger)
	server := &Server{
		logger: logger,
	}
	server.authCookie = make(map[string]AuthCookie)

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
