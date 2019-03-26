package apiserver

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"

	"github.com/ti-mo/conntracct/internal/pipeline"
)

var (
	// Processing pipeline handle
	pipe *pipeline.Pipeline

	// Whether or not package was successfully initialized
	initSuccess bool
)

// Init configures the package with handles to the objects it manipulates.
func Init(p *pipeline.Pipeline) error {

	if p != nil {
		pipe = p
	} else {
		return errNoPipe
	}

	// Mark package as initialized
	initSuccess = true

	return nil
}

// Run the HTTP listener.
func Run(addr string) error {

	// Check if the package was properly initialized
	if !initSuccess {
		return errNotInit
	}

	r := mux.NewRouter()

	r.HandleFunc("/stats", HandleStats)

	http.Handle("/", r)
	go func() {
		if err := http.ListenAndServe(addr, r); err != nil {
			log.Fatalf("Error in http listener: %s", err)
		}
	}()

	log.Infof("API server listening on address '%s'", addr)

	return nil
}
