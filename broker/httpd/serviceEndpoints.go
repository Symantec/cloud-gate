package httpd

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

func (s *Server) getPreferredAcceptType(r *http.Request) string {
	preferredAcceptType := "application/json"
	acceptHeader, ok := r.Header["Accept"]
	if ok {
		for _, acceptValue := range acceptHeader {
			if strings.Contains(acceptValue, "text/html") {
				s.logger.Debugf(2, "Got it  %+v", acceptValue)
				preferredAcceptType = "text/html"
			}
		}
	}
	return preferredAcceptType
}

func (s *Server) consoleAccessHandler(w http.ResponseWriter, r *http.Request) {
	authUser, err := s.getRemoteUserName(w, r)
	if err != nil {
		return
	}

	err = r.ParseForm()
	if err != nil {
		s.logger.Println(err)
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	mode := "webConsole"
	valueArr, ok := r.Form["mode"]
	if ok {
		mode = valueArr[0]
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
	if mode == "genToken" {
		displayData.TokenConsole = true
	}
	returnAcceptType := s.getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":

		w.Header().Set("Cache-Control", "private, max-age=30")
		err = s.htmlTemplate.ExecuteTemplate(w, "consoleAccessPage", displayData)
		if err != nil {
			s.logger.Printf("Failed to execute %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	default:
		displayData.Title = ""
		b, err := json.MarshalIndent(displayData, "", "  ")
		if err != nil {
			s.logger.Printf("Failed marshal %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return

		}
		_, err = w.Write(b)
		if err != nil {
			s.logger.Printf("Incomplete write? %v", err)
		}
	}
	return
}

// Assumes the form is alreadty parsed.
func (s *Server) getVerifyFormValues(r *http.Request, formKey []string, retext string) (map[string][]string, error) {
	var m map[string][]string
	m = make(map[string][]string)

	for _, key := range formKey {
		valueArr, ok := r.Form[key]
		if !ok {
			return nil, errors.New("Missing required parameter")
		}
		for _, value := range valueArr {

			ok, err := regexp.MatchString(retext, value)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errors.New("Missing invalid parameter")
			}
		}
		m[key] = valueArr
	}

	return m, nil
}

func (s *Server) getConsoleUrlHandler(w http.ResponseWriter, r *http.Request) {
	authUser, err := s.getRemoteUserName(w, r)
	if err != nil {
		return
	}
	if !(r.Method == "POST" || r.Method == "GET") {
		s.logger.Printf("Invalid method for getConsole username for %s", authUser)
		http.Error(w, "error", http.StatusMethodNotAllowed)
		return
	}
	err = r.ParseForm()
	if err != nil {
		s.logger.Println(err)
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	validatedParams, err := s.getVerifyFormValues(r, []string{"accountName", "roleName"}, "^[A-Za-z0-9_.-]{2,40}$")
	if err != nil {
		s.logger.Println(err)
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	accountName := validatedParams["accountName"][0]
	roleName := validatedParams["roleName"][0]

	ok, err := s.brokers["aws"].IsUserAllowedToAssumeRole(authUser, accountName, roleName)
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

func (s *Server) generateTokenHandler(w http.ResponseWriter, r *http.Request) {
	authUser, err := s.getRemoteUserName(w, r)
	if err != nil {
		return
	}
	// TODO: check for valid method
	err = r.ParseForm()
	if err != nil {
		s.logger.Println(err)
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	validatedParams, err := s.getVerifyFormValues(r, []string{"accountName", "roleName"}, "^[A-Za-z0-9_.-]{2,40}$")
	if err != nil {
		s.logger.Println(err)
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	accountName := validatedParams["accountName"][0]
	roleName := validatedParams["roleName"][0]

	ok, err := s.brokers["aws"].IsUserAllowedToAssumeRole(authUser, accountName, roleName)
	if !ok {
		http.Error(w, "Invalid account or Role", http.StatusForbidden)
		return
	}
	tempCredentials, err := s.brokers["aws"].GenerateTokenCredentials(accountName, roleName, authUser)
	if err != nil {
		s.logger.Printf("Failed to get token %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return

	}

	returnAcceptType := s.getPreferredAcceptType(r)
	switch returnAcceptType {
	case "text/html":
		displayData := generateTokenPageTemplateData{
			Title:        "Cloud-Gate credential output",
			AuthUsername: authUser,
			AccountName:  accountName,
			RoleName:     roleName,
			SessionId:    tempCredentials.SessionId,
			SessionKey:   tempCredentials.SessionKey,
			SessionToken: tempCredentials.SessionToken,
			Region:       tempCredentials.Region,
		}

		err = s.htmlTemplate.ExecuteTemplate(w, "generateTokenPagePage", displayData)
		if err != nil {
			s.logger.Printf("Failed to execute %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	default:

		b, err := json.MarshalIndent(tempCredentials, "", "  ")
		if err != nil {
			s.logger.Printf("Failed marshal %v", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return

		}
		_, err = w.Write(b)
		if err != nil {
			s.logger.Printf("Incomplete write? %v", err)
		}
	}
	return

}
