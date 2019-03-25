package apiserver

import (
	"encoding/json"
	"net/http"

	"github.com/ti-mo/conntracct/internal/sinks/types"
)

// HandleStats returns statistics about the application in JSON format.
func HandleStats(w http.ResponseWriter, r *http.Request) {

	probe := pipe.ProbeStats()
	pline := pipe.Stats()

	sinks := make(map[string]types.SinkStats)
	for _, s := range pipe.GetSinks() {
		sinks[s.Name()] = s.Stats()
	}

	s := map[string]interface{}{
		"probe":    probe,
		"pipeline": pline,
		"sinks":    sinks,
	}

	out, err := json.Marshal(s)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		write(w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	write(w, "%s", out)
}
