package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// previewBody trims and truncates response bodies for readable logs.
func previewBody(body []byte, maxLen int) string {
	if maxLen < 8 {
		maxLen = 8
	}
	s := strings.TrimSpace(string(body))
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}

// encodePathForURL escapes each path segment but preserves "/" separators.
func encodePathForURL(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

// normalizeContentPath converts user-provided path values into canonical relative paths.
func normalizeContentPath(p string) string {
	trimmed := strings.TrimSpace(p)
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "." {
		return ""
	}
	return trimmed
}

// openIncognito attempts to open the UI in a private browser window (OS/browser dependent).
// It tries a list of known browser commands and returns aggregated errors if all fail.
func openIncognito(appURL string) error {
	var commands [][]string

	switch runtime.GOOS {
	case "darwin":
		commands = [][]string{
			{"open", "-na", "Google Chrome", "--args", "--incognito", appURL},
			{"open", "-na", "Microsoft Edge", "--args", "--inprivate", appURL},
			{"open", "-na", "Chromium", "--args", "--incognito", appURL},
			{"open", "-na", "Firefox", "--args", "--private-window", appURL},
		}
	case "windows":
		commands = [][]string{
			{"cmd", "/c", "start", "chrome", "--incognito", appURL},
			{"cmd", "/c", "start", "msedge", "--inprivate", appURL},
			{"cmd", "/c", "start", "firefox", "-private-window", appURL},
		}
	default:
		commands = [][]string{
			{"google-chrome", "--incognito", appURL},
			{"chromium-browser", "--incognito", appURL},
			{"chromium", "--incognito", appURL},
			{"microsoft-edge", "--inprivate", appURL},
			{"brave-browser", "--incognito", appURL},
			{"firefox", "--private-window", appURL},
		}
	}

	var errs []string
	for _, cmdArgs := range commands {
		if len(cmdArgs) == 0 {
			continue
		}
		if _, err := exec.LookPath(cmdArgs[0]); err != nil {
			errs = append(errs, fmt.Sprintf("%s not found", cmdArgs[0]))
			continue
		}

		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if err := cmd.Start(); err == nil {
			return nil
		} else {
			errs = append(errs, fmt.Sprintf("%s failed: %v", cmdArgs[0], err))
		}
	}

	return errors.New(strings.Join(errs, "; "))
}

// openRegularBrowser opens a normal browser tab/window for a target URL.
// Used to open GitHub activation page from backend side.
func openRegularBrowser(targetURL string) error {
	var commands [][]string

	switch runtime.GOOS {
	case "darwin":
		commands = [][]string{
			{"open", targetURL},
		}
	case "windows":
		commands = [][]string{
			{"cmd", "/c", "start", "", targetURL},
		}
	default:
		commands = [][]string{
			{"xdg-open", targetURL},
			{"gio", "open", targetURL},
		}
	}

	var errs []string
	for _, cmdArgs := range commands {
		if len(cmdArgs) == 0 {
			continue
		}
		if _, err := exec.LookPath(cmdArgs[0]); err != nil {
			errs = append(errs, fmt.Sprintf("%s not found", cmdArgs[0]))
			continue
		}
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		startErr := cmd.Start()
		if startErr == nil {
			return nil
		}
		errs = append(errs, fmt.Sprintf("%s failed: %v", cmdArgs[0], startErr))
	}
	return errors.New(strings.Join(errs, "; "))
}

// randomHex returns cryptographically random bytes encoded as lowercase hex.
func randomHex(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// getEnv returns trimmed env value or provided fallback when empty.
func getEnv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

// serverURLFromAddr turns listen addr into a browser-openable local URL.
func serverURLFromAddr(addr string) string {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return "http://localhost:8080"
	}
	if strings.HasPrefix(trimmed, ":") {
		return "http://localhost" + trimmed
	}
	if strings.HasPrefix(trimmed, "127.0.0.1:") || strings.HasPrefix(trimmed, "localhost:") {
		return "http://" + trimmed
	}
	return "http://localhost:8080"
}

// writeJSON writes JSON with status and content-type; encoding errors are ignored intentionally.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// decodeJSONBodyIfPresent supports optional JSON bodies for endpoints.
// Empty body is treated as "no payload" rather than an error.
func decodeJSONBodyIfPresent(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil
	}
	return json.Unmarshal(body, dst)
}

// logRequests is middleware that prints one access log line per request.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
