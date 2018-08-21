package httpd

import (
	"net/http"
	"regexp"
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

func (s *Server) getConsoleUrlHandler(w http.ResponseWriter, r *http.Request) {
	authUser, err := s.getRemoteUserName(w, r)
	if err != nil {
		return
	}

	if !(r.Method == "POST" || r.Method == "GET") {
		s.logger.Printf("Invalid metdhor for getConsole username for %s", authUser)
		http.Error(w, "error", http.StatusMethodNotAllowed)
		return
	}

	err = r.ParseForm()
	if err != nil {
		s.logger.Println(err)
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	accountNameArr, ok := r.Form["accountName"]
	if !ok {
		http.Error(w, "Missing required parameter accountName", http.StatusBadRequest)
		return
	}
	accountName := accountNameArr[0]
	ok, err = regexp.MatchString("^[A-Za-z0-9_.-]{2,40}$", accountName)
	if !ok {
		http.Error(w, "badAccountName", http.StatusBadRequest)
		return
	}
	roleNameArr, ok := r.Form["roleName"]
	if !ok {
		http.Error(w, "Missing required parameter roleName", http.StatusBadRequest)
		return
	}
	roleName := roleNameArr[0]
	ok, err = regexp.MatchString("^[A-Za-z0-9_.-]{2,40}$", roleName)
	if !ok {
		http.Error(w, "badRoleName", http.StatusBadRequest)
		return
	}

	ok, err = s.brokers["aws"].UserAllowedToAssumeRole(authUser, accountName, roleName)
	if !ok {
		http.Error(w, "Invalid account or Role", http.StatusForbidden)
		return
	}
	destUrl, err := s.brokers["aws"].GetConsoleURLForAccountRole(accountName, roleName, authUser)
	if err != nil {
		s.logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}
	http.Redirect(w, r, destUrl, 302)
	return
}
