package httpd

import (
	"time"
)

func (s *Server) performStateCleanup(secsBetweenCleanup int) {
	for {
		s.cookieMutex.Lock()
		for key, authCookie := range s.authCookie {
			if authCookie.ExpiresAt.Before(time.Now()) {
				delete(s.authCookie, key)
			}
		}
		s.cookieMutex.Unlock()
		time.Sleep(time.Duration(secsBetweenCleanup) * time.Second)
	}
}
