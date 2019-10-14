package pprof

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	// side effect of registering HTTP handler in default ServeMux
	_ "net/http/pprof" //nolint:gosec
)

// ListenAndServe starts a pprof endpoint on the given addr
// and replaces the global http.DefaultServeMux with a new instance.
func ListenAndServe(addr string) {

	// Save a reference to the default global ServeMux.
	ppm := http.DefaultServeMux

	// Replace the default ServeMux with a new instance.
	http.DefaultServeMux = http.NewServeMux()

	// Start pprof server on global ServeMux.
	go func() {
		log.Fatal(http.ListenAndServe(addr, ppm))
	}()
}
