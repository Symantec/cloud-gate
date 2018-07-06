package httpd

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
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
	// If you have a verified cert, no need for cookies
	if r.TLS != nil {
		if len(r.TLS.VerifiedChains) > 0 {
			clientName := r.TLS.VerifiedChains[0][0].Subject.CommonName
			return clientName, nil
		}
	}

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
		return "", errors.New("Cookie not found")
	}
	if authInfo.ExpiresAt.Before(time.Now()) {
		http.Redirect(w, r, loginPath, http.StatusFound)
		return "", errors.New("Expired Cookie")
	}
	return authInfo.Username, nil
}
