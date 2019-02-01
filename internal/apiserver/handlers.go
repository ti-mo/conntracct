package apiserver

import (
	"net/http"
)

// HandleStats returns statistics about the application.
func HandleStats(w http.ResponseWriter, r *http.Request) {

	w.WriteHeader(http.StatusOK)

	write(w, "Pipeline: %v\n", pipe.Stats)

	for _, s := range pipe.GetSinks() {
		write(w, "Sink '%s': %v\n", s.Name(), s.Stats())
	}
}
