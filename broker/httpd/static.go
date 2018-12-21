package httpd

import (
	"fmt"
	"net/http"
)

func staticHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/static/common.css":
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Cache-Control", "public, max-age=120")
		fmt.Fprintf(w, "%s", commonCSS)
		return
	}
	http.Error(w, "error not found", http.StatusNotFound)
}
