package httpd

import (
	"bufio"
	"fmt"
	"net/http"
)

func (s *Server) dashboardRootHandler(w http.ResponseWriter, req *http.Request) {
	writer := bufio.NewWriter(w)
	defer writer.Flush()
	fmt.Fprintln(writer, "<title>cloud-gate</title>")
	fmt.Fprintln(writer, `<style>
                          table, th, td {
                          border-collapse: collapse;
                          }
                          </style>`)
	fmt.Fprintln(writer, "<body>")
	fmt.Fprintln(writer, "<center>")
	fmt.Fprintln(writer, "<h1>cloud-gate UI. Under Construction.</h1>")
	fmt.Fprintln(writer, "<hr>")
	fmt.Fprintln(writer, "<a href=\"status\">Status page</a>")
	fmt.Fprintln(writer, "</center>")
	fmt.Fprintln(writer, "</body>")
}
