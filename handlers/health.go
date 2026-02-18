package handlers

import (
	"encoding/json"
	"net/http"
	"time"
)

func Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "ok",
		"service":   "sentinent-backend",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
