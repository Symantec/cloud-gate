package httpd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

func staticHandler(w http.ResponseWriter, r *http.Request) {
	//log.Printf("Top of Static Handler")
	switch r.URL.Path {
	case "/static/common.css":
		w.Header().Set("Content-Type", "text/css")
		fmt.Fprintf(w, "%s", commonCSS)
		return

	case "/static/customization.css":
		w.Header().Set("Content-Type", "text/css")
		fmt.Fprintf(w, "%s", customizationCSS)
		return
	}
	http.Error(w, "error not found", http.StatusNotFound)
}

func randomStringGeneration() (string, error) {
	const size = 32
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	userInfo, err := s.authSource.GetRemoteUserInfo(r)
	if err != nil {
		s.logger.Println(err)
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if userInfo == nil {
		s.logger.Println("null userinfo!")

		http.Error(w, "null userinfo", http.StatusInternalServerError)
		return
	}
	randomString, err := randomStringGeneration()
	if err != nil {
		s.logger.Println(err)
		http.Error(w, "cannot generate random string", http.StatusInternalServerError)
		return
	}

	expires := time.Now().Add(time.Hour * cookieExpirationHours)

	userCookie := http.Cookie{Name: authCookieName, Value: randomString, Path: "/", Expires: expires, HttpOnly: true, Secure: true}

	http.SetCookie(w, &userCookie)

	Cookieinfo := AuthCookie{*userInfo.Username, userCookie.Expires}

	s.cookieMutex.Lock()
	s.authCookie[userCookie.Value] = Cookieinfo
	s.cookieMutex.Unlock()

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) GetRemoteUserName(w http.ResponseWriter, r *http.Request) (string, error) {

	remoteCookie, err := r.Cookie(authCookieName)
	if err != nil {
		s.logger.Println(err)
		http.Redirect(w, r, loginPath, http.StatusFound)
		return "", err
	}
	s.cookieMutex.Lock()
	defer s.cookieMutex.Unlock()
	authInfo, ok := s.authCookie[remoteCookie.Value]

	if !ok {
		http.Redirect(w, r, loginPath, http.StatusFound)
		return "", nil
	}
	if authInfo.ExpiresAt.Before(time.Now()) {
		http.Redirect(w, r, loginPath, http.StatusFound)
		return "", nil
	}
	return authInfo.Username, nil
}

func (s *Server) consoleAccessHandler(w http.ResponseWriter, r *http.Request) {
	authUser, err := s.GetRemoteUserName(w, r)
	if err != nil {
		return
	}

	displayData := consolePageTemplateData{
		Title:        "Cloud-Gate console access",
		AuthUsername: authUser,
	}
	err = s.htmlTemplate.ExecuteTemplate(w, "consoleAccessPage", displayData)
	if err != nil {
		s.logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	return
}
