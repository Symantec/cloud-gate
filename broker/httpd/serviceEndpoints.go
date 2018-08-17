package httpd

import (
	"net/http"
)

func (s *Server) consoleAccessHandler(w http.ResponseWriter, r *http.Request) {
	authUser, err := s.getRemoteUserName(w, r)
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
