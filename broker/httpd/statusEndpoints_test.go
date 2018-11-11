package httpd

import (
	//"encoding/json"
	//"errors"
	//"fmt"
	"html/template"
	//"io/ioutil"
	stdlog "log"
	"net/http"
	//"net/http/httptest"
	//"net/url"
	"os"
	"testing"
	"time"

	"github.com/Symantec/Dominator/lib/log/debuglogger"
	"github.com/Symantec/cloud-gate/broker/staticconfiguration"
	//"golang.org/x/net/context"
	//"golang.org/x/oauth2"
)

var test_footer_extra = `{{define "footer_extra"}}{{end}}`
var test_header_extra = `{{define "header_extra"}}{{end}}`

func TestUnsealingHandler(t *testing.T) {
	slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	logger := debuglogger.New(slogger)
	server := &Server{
		logger:       logger,
		staticConfig: &staticconfiguration.StaticConfiguration{},
	}
	server.authCookie = make(map[string]AuthCookie)
	server.staticConfig.Base.SharedSecrets = []string{"secret"}

	server.htmlTemplate = template.New("main")
	//also add templates
	/// Load the oter built in templates
	extraTemplates := []string{footerTemplateText,
		consoleAccessTemplateText,
		generateTokaneTemplateText,
		unsealingFormPageTemplateText,
		headerTemplateText,
		test_header_extra,
		test_footer_extra}
	for _, templateString := range extraTemplates {
		_, err := server.htmlTemplate.Parse(templateString)
		if err != nil {
			//return nil, err
			t.Fatal(err)
		}
	}

	//now succeed with known cookie
	cookieVal := "xxxxx"
	expires := time.Now().Add(time.Hour * cookieExpirationHours)
	Cookieinfo := AuthCookie{"username", expires}
	server.authCookie[cookieVal] = Cookieinfo
	knownCookieReq, err := http.NewRequest("GET", "/unseal", nil)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	knownCookieReq.AddCookie(&authCookie)

	_, err = checkRequestHandlerCode(knownCookieReq, server.unsealingHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	/*

		_, err = checkRequestHandlerCode(knownCookieReq, func(w http.ResponseWriter, r *http.Request) {
			_, err := server.unsealingHandler(w, r)
			if err != nil {
				t.Fatal("GetRemoteUsername should have failed")
			}
		}, http.StatusFound)
	*/
}
