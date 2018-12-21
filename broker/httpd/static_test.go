package httpd

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func checkRequestHandlerCode(req *http.Request, handlerFunc http.HandlerFunc, expectedStatus int) (*httptest.ResponseRecorder, error) {
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlerFunc)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != expectedStatus {
		errStr := fmt.Sprintf("handler returned wrong status code: got %v want %v",
			status, expectedStatus)
		err := errors.New(errStr)
		return nil, err
	}
	return rr, nil
}

func TestStaticHandler(t *testing.T) {
	urlList := []string{"/static/common.css"}
	for _, url := range urlList {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = checkRequestHandlerCode(req, staticHandler, http.StatusOK)
		if err != nil {
			t.Fatal(err)
		}
	}
	// check for notfound
	req, err := http.NewRequest("GET", "/foobar", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, staticHandler, http.StatusNotFound)
	if err != nil {
		t.Fatal(err)
	}
}
