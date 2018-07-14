package pprof

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	// side effect of registering HTTP handler in default ServeMux
	_ "net/http/pprof"
)

// ListenAndServe starts a pprof endpoint on localhost:6060
// and replaces the global http.DefaultServeMux with a new instance.
func ListenAndServe() {

	// Save a reference to the default global ServeMux
	ppm := http.DefaultServeMux

	// Replace the default ServeMux with a new instance
	http.DefaultServeMux = http.NewServeMux()

	// Start pprof server on global ServeMux
	go func() {
		log.Fatal(http.ListenAndServe("localhost:6060", ppm))
	}()
}
