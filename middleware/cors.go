package middleware

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var allowedOrigins = map[string]struct{}{}

func SetAllowedOrigins(origins []string) error {
	normalizedOrigins := make(map[string]struct{}, len(origins))

	for _, origin := range origins {
		if strings.TrimSpace(origin) == "" {
			continue
		}
		normalizedOrigin, err := normalizeOrigin(origin)
		if err != nil {
			return err
		}
		normalizedOrigins[normalizedOrigin] = struct{}{}
	}

	if len(normalizedOrigins) == 0 {
		return fmt.Errorf("at least one valid CORS origin is required")
	}

	allowedOrigins = normalizedOrigins
	return nil
}

func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		originAllowed := false
		normalizedOrigin := ""

		if origin != "" {
			var err error
			normalizedOrigin, err = normalizeOrigin(origin)
			if err == nil {
				_, originAllowed = allowedOrigins[normalizedOrigin]
			}

			if originAllowed {
				setCORSHeaders(w, normalizedOrigin)
			} else if r.Method == http.MethodOptions {
				http.Error(w, "CORS origin denied", http.StatusForbidden)
				return
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func setCORSHeaders(w http.ResponseWriter, origin string) {
	addVaryHeader(w, "Origin")
	addVaryHeader(w, "Access-Control-Request-Method")
	addVaryHeader(w, "Access-Control-Request-Headers")
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func addVaryHeader(w http.ResponseWriter, value string) {
	for _, existing := range w.Header().Values("Vary") {
		for _, part := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(part), value) {
				return
			}
		}
	}
	w.Header().Add("Vary", value)
}

func normalizeOrigin(origin string) (string, error) {
	trimmedOrigin := strings.TrimSpace(origin)
	if trimmedOrigin == "" {
		return "", fmt.Errorf("empty CORS origin")
	}

	parsed, err := url.Parse(trimmedOrigin)
	if err != nil {
		return "", fmt.Errorf("invalid CORS origin %q: %w", trimmedOrigin, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid CORS origin %q", trimmedOrigin)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("CORS origin must not contain a path: %q", trimmedOrigin)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return "", fmt.Errorf("CORS origin must only include scheme and host: %q", trimmedOrigin)
	}

	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), nil
}
