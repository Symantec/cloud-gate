package httpd

import (
	"fmt"
	"net/http"
)

func staticHandler(w http.ResponseWriter, r *http.Request) {
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
