package apiserver

import (
	"fmt"
	"net/http"
)

// HandleStats returns statistics about the application.
func HandleStats(w http.ResponseWriter, r *http.Request) {

	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "Pipeline: %v\n", pipe.Stats)

	for _, s := range pipe.GetAcctSinks() {
		fmt.Fprintf(w, "Sink '%s': %v\n", s.Name(), s.Stats())
	}
}
