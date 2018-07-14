package apiserver

import (
	"fmt"
	"net/http"
)

// HandleStats returns statistics about the application.
func HandleStats(w http.ResponseWriter, r *http.Request) {

	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "Pipeline: %v\n", pipe.Stats)
}
