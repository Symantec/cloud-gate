package httpd

import (
	"net/http"
)

func (s *Server) consoleAccessHandler(w http.ResponseWriter, r *http.Request) {
	authUser, err := s.getRemoteUserName(w, r)
	if err != nil {
		return
	}
	userAccounts, err := s.brokers["aws"].GetUserAllowedAccounts(authUser)
	if err != nil {
		s.logger.Printf("Failed to get aws accounts for %s, err=%v", authUser, err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	cloudAccounts := make(map[string]cloudAccountInfo)
	for _, account := range userAccounts {
		cloudAccounts[account.HumanName] = cloudAccountInfo{Name: account.Name,
			AvailableRoles: account.PermittedRoleName}
	}

	displayData := consolePageTemplateData{
		Title:         "Cloud-Gate console access",
		AuthUsername:  authUser,
		CloudAccounts: cloudAccounts,
	}
	err = s.htmlTemplate.ExecuteTemplate(w, "consoleAccessPage", displayData)
	if err != nil {
		s.logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	return
}
