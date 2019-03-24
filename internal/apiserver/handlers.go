package apiserver

import (
	"encoding/json"
	"net/http"
)

// HandleStats returns statistics about the application.
func HandleStats(w http.ResponseWriter, r *http.Request) {

	w.WriteHeader(http.StatusOK)

	jps, _ := json.Marshal(pipe.Stats())
	write(w, "Pipeline: %s\n", jps)

	for _, s := range pipe.GetSinks() {
		jss, _ := json.Marshal(s.Stats())
		write(w, "Sink '%s': %s\n", s.Name(), jss)
	}
}
