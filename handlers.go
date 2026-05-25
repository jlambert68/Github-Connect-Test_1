package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleIndex serves the single-page UI and ensures a backend session id exists.
func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	a.ensureSessionID(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexHTML)
}

// handleAuthStatus reports whether the current browser session can use a valid token.
// It can restore identity from memory, cookies, or DB fallback before checking token access.
func (a *app) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := a.getSessionID(r)
	if !ok {
		sessionID = a.ensureSessionID(w, r)
	}

	identity, hasIdentity := a.getOrRestoreSessionIdentityWithSessionID(sessionID, r)
	if !hasIdentity {
		// No known identity for this session, so user is not authenticated yet.
		writeJSON(w, http.StatusOK, map[string]any{
			"logged_in":   false,
			"session_id":  sessionID,
			"token_found": false,
			"user_login":  "",
			"user_id":     "",
			"user_name":   "",
		})
		return
	}
	// Refresh identity cookies so returning sessions stay sticky.
	a.setIdentityCookies(w, identity)

	// "Logged in" means we can actually obtain a verified decrypted token.
	_, err := a.getDecryptedTokenForUser(r.Context(), identity.UserID, identity.UserLogin)
	tokenFound := err == nil
	userErr := ""
	if err != nil {
		userErr = err.Error()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"logged_in":   tokenFound,
		"session_id":  sessionID,
		"token_found": tokenFound,
		"user_login":  identity.UserLogin,
		"user_id":     identity.UserID,
		"user_name":   identity.UserName,
		"user_error":  userErr,
	})
}

// handleUserRepos loads repositories visible to the authenticated user.
func (a *app) handleUserRepos(w http.ResponseWriter, r *http.Request) {
	sessionID := a.ensureSessionID(w, r)
	identity, ok := a.getOrRestoreSessionIdentityWithSessionID(sessionID, r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not available in this session"})
		return
	}

	token, err := a.getDecryptedTokenForUser(r.Context(), identity.UserID, identity.UserLogin)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token unavailable: " + err.Error()})
		return
	}

	repos, err := a.listUserRepos(r.Context(), token)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"repos": repos,
	})
}

// handleOpenGitHubDeviceBrowser asks the OS to open GitHub device activation page.
func (a *app) handleOpenGitHubDeviceBrowser(w http.ResponseWriter, r *http.Request) {
	const loginURL = "https://github.com/login/device"
	if err := openRegularBrowser(loginURL); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"opened": false,
			"url":    loginURL,
			"error":  err.Error(),
		})
		return
	}
	log.Printf("opened GitHub device login in regular browser: %s", loginURL)
	writeJSON(w, http.StatusOK, map[string]any{
		"opened": true,
		"url":    loginURL,
	})
}

// handleGitHubDeviceStart starts device flow unless session already has a usable token.
func (a *app) handleGitHubDeviceStart(w http.ResponseWriter, r *http.Request) {
	sessionID := a.ensureSessionID(w, r)

	identity, hasIdentity := a.getOrRestoreSessionIdentityWithSessionID(sessionID, r)
	if hasIdentity {
		// Skip login dance if this session is already authenticated end-to-end.
		if _, err := a.getDecryptedTokenForUser(r.Context(), identity.UserID, identity.UserLogin); err == nil {
			log.Printf("device flow start skipped: existing token found for session_id=%s user_id=%s", sessionID, identity.UserID)
			writeJSON(w, http.StatusOK, map[string]any{
				"status":  "already_authenticated",
				"message": "session already has a github token",
			})
			return
		}
	}

	deviceCodeResp, err := a.requestDeviceCode(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	flowID, err := randomHex(16)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create flow id"})
		return
	}
	if deviceCodeResp.ExpiresIn <= 0 {
		deviceCodeResp.ExpiresIn = 900
	}
	if deviceCodeResp.Interval <= 0 {
		deviceCodeResp.Interval = 5
	}

	flow := &deviceFlow{
		ID:                      flowID,
		SessionID:               sessionID,
		DeviceCode:              deviceCodeResp.DeviceCode,
		UserCode:                deviceCodeResp.UserCode,
		VerificationURI:         deviceCodeResp.VerificationURI,
		VerificationURIComplete: deviceCodeResp.VerificationURIComplete,
		ExpiresAt:               time.Now().Add(time.Duration(deviceCodeResp.ExpiresIn) * time.Second),
		Interval:                time.Duration(deviceCodeResp.Interval) * time.Second,
		Status:                  "pending",
	}

	// Store flow state so frontend can poll by flow_id.
	a.mu.Lock()
	a.deviceFlows[flowID] = flow
	a.mu.Unlock()

	go a.pollDeviceFlow(flowID)

	// Return all UX data needed to complete activation.
	writeJSON(w, http.StatusOK, map[string]any{
		"flow_id":                   flowID,
		"user_code":                 flow.UserCode,
		"verification_uri":          flow.VerificationURI,
		"verification_uri_complete": flow.VerificationURIComplete,
		"expires_in":                deviceCodeResp.ExpiresIn,
		"interval":                  int(flow.Interval.Seconds()),
		"status":                    flow.Status,
	})
}

// handleGitHubDeviceStatus lets frontend poll the status of a previously started flow.
func (a *app) handleGitHubDeviceStatus(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := a.getSessionID(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not logged in"})
		return
	}

	flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))
	if flowID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "flow_id is required"})
		return
	}

	a.mu.RLock()
	flow, ok := a.deviceFlows[flowID]
	a.mu.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "flow not found"})
		return
	}
	if flow.SessionID != sessionID {
		// Prevent one browser session from reading another session's flow state.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "flow does not belong to this session"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"flow_id":                   flow.ID,
		"status":                    flow.Status,
		"user_code":                 flow.UserCode,
		"verification_uri":          flow.VerificationURI,
		"verification_uri_complete": flow.VerificationURIComplete,
		"access_token":              flow.AccessToken,
		"error":                     flow.Error,
	})
}

// handleRegisterToken is called after frontend receives an access token from device flow.
// It re-resolves the user on backend, verifies token hash, encrypts token, stores in DB, and caches.
func (a *app) handleRegisterToken(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := a.getSessionID(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not logged in"})
		return
	}

	var req struct {
		AccessToken string `json:"access_token"`
		TokenHash   string `json:"token_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	req.AccessToken = strings.TrimSpace(req.AccessToken)
	req.TokenHash = strings.TrimSpace(strings.ToLower(req.TokenHash))
	if req.AccessToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "access_token is required"})
		return
	}
	if req.TokenHash == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token_hash is required"})
		return
	}

	user, err := a.fetchAuthenticatedUser(r.Context(), req.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to resolve github user from token: " + err.Error()})
		return
	}
	userID := strconv.FormatInt(user.ID, 10)
	if userID == "0" || strings.TrimSpace(user.Login) == "" {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "github user response missing id/login"})
		return
	}
	expectedHash := hashUserLoginAndToken(strings.TrimSpace(user.Login), req.AccessToken)
	if req.TokenHash != expectedHash {
		// Security check: frontend user+token hash must match backend recomputation.
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "token hash mismatch between frontend and backend",
		})
		return
	}

	encryptedToken, err := a.encryptToken(req.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encrypt token: " + err.Error()})
		return
	}
	if err := a.upsertEncryptedTokenInDB(userID, user.Login, encryptedToken, expectedHash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist encrypted token: " + err.Error()})
		return
	}

	identity := sessionIdentity{
		UserID:    userID,
		UserLogin: strings.TrimSpace(user.Login),
		UserName:  strings.TrimSpace(user.Name),
	}
	// Update all runtime state: encrypted token cache, hash cache, and session identity.
	a.mu.Lock()
	a.encryptedTokenCache[userID] = encryptedToken
	loginKey := strings.ToLower(strings.TrimSpace(user.Login))
	a.tokenHashCache[loginKey] = expectedHash
	a.sessionUser[sessionID] = identity
	a.mu.Unlock()
	a.setIdentityCookies(w, identity)

	log.Printf("token registered: session_id=%s user_id=%s login=%s token_len=%d", sessionID, userID, user.Login, len(req.AccessToken))

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "token stored encrypted",
		"user_id":    userID,
		"user_login": user.Login,
		"user_name":  user.Name,
	})
}

// handleListRepo lists files/folders for a repo path using the authenticated user's token.
func (a *app) handleListRepo(w http.ResponseWriter, r *http.Request) {
	sessionID := a.ensureSessionID(w, r)
	identity, ok := a.getOrRestoreSessionIdentityWithSessionID(sessionID, r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not available in this session"})
		return
	}

	token, err := a.getDecryptedTokenForUser(r.Context(), identity.UserID, identity.UserLogin)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token unavailable: " + err.Error()})
		return
	}

	var reqBody struct {
		Owner string `json:"owner"`
		Repo  string `json:"repo"`
		Ref   string `json:"ref"`
		Path  string `json:"path"`
	}
	if err := decodeJSONBodyIfPresent(r, &reqBody); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	owner := strings.TrimSpace(reqBody.Owner)
	repo := strings.TrimSpace(reqBody.Repo)
	ref := strings.TrimSpace(reqBody.Ref)
	contentPath := normalizeContentPath(reqBody.Path)
	if owner == "" {
		// Fallback defaults support quick testing with env configuration.
		owner = strings.TrimSpace(a.cfg.RepoOwner)
	}
	if repo == "" {
		repo = strings.TrimSpace(a.cfg.RepoName)
	}
	if ref == "" {
		ref = strings.TrimSpace(a.cfg.RepoRef)
	}
	if ref == "" {
		ref = "main"
	}
	if owner == "" || repo == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "owner and repo are required (pass in request body or set GITHUB_REPO_OWNER/GITHUB_REPO_NAME)",
		})
		return
	}

	log.Printf("list repo requested: owner=%s repo=%s ref=%s path=%q session_id=%s", owner, repo, ref, contentPath, sessionID)

	entries, err := a.listRepoAndPrint(r.Context(), token, owner, repo, ref, contentPath)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	displayPath := "/"
	if contentPath != "" {
		displayPath = "/" + contentPath
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"entry_count": len(entries),
		"entries":     entries,
		"owner":       owner,
		"repo":        repo,
		"ref":         ref,
		"path":        contentPath,
		"displayPath": displayPath,
	})
}

// handleFileContent fetches and returns file text for a concrete repo path.
func (a *app) handleFileContent(w http.ResponseWriter, r *http.Request) {
	sessionID := a.ensureSessionID(w, r)
	identity, ok := a.getOrRestoreSessionIdentityWithSessionID(sessionID, r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not available in this session"})
		return
	}

	token, err := a.getDecryptedTokenForUser(r.Context(), identity.UserID, identity.UserLogin)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token unavailable: " + err.Error()})
		return
	}

	var reqBody struct {
		Owner string `json:"owner"`
		Repo  string `json:"repo"`
		Ref   string `json:"ref"`
		Path  string `json:"path"`
	}
	if err := decodeJSONBodyIfPresent(r, &reqBody); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}

	owner := strings.TrimSpace(reqBody.Owner)
	repo := strings.TrimSpace(reqBody.Repo)
	ref := strings.TrimSpace(reqBody.Ref)
	filePath := normalizeContentPath(reqBody.Path)
	if owner == "" || repo == "" || filePath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "owner, repo and path are required",
		})
		return
	}
	if ref == "" {
		ref = "main"
	}

	content, err := a.fetchFileContent(r.Context(), token, owner, repo, ref, filePath)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	fullPath := owner + "/" + repo + "/" + filePath
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"full_path":   fullPath,
		"content":     content,
		"owner":       owner,
		"repo":        repo,
		"ref":         ref,
		"path":        filePath,
		"displayPath": "/" + filePath,
	})
}

// handleClearTokenMemory clears only in-memory caches for the current session user.
// The encrypted token remains persisted in SQLite and can be reloaded later.
func (a *app) handleClearTokenMemory(w http.ResponseWriter, r *http.Request) {
	sessionID := a.ensureSessionID(w, r)
	identity, ok := a.getOrRestoreSessionIdentityWithSessionID(sessionID, r)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session user not found"})
		return
	}

	a.mu.Lock()
	delete(a.encryptedTokenCache, identity.UserID)
	delete(a.tokenHashCache, strings.ToLower(identity.UserLogin))
	a.mu.Unlock()

	log.Printf("cleared encrypted token from memory cache: user_id=%s login=%s", identity.UserID, identity.UserLogin)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "memory cache cleared",
		"user_id":    identity.UserID,
		"user_login": identity.UserLogin,
	})
}

// handleClearTokenMemoryAndDB removes both runtime cache and persisted token record.
// It also clears auth cookies so UI returns to logged-out state.
func (a *app) handleClearTokenMemoryAndDB(w http.ResponseWriter, r *http.Request) {
	sessionID := a.ensureSessionID(w, r)
	identity, ok := a.getOrRestoreSessionIdentityWithSessionID(sessionID, r)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session user not found"})
		return
	}

	if err := a.deleteEncryptedTokenFromDB(identity.UserID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to remove token from database: " + err.Error()})
		return
	}

	a.mu.Lock()
	delete(a.encryptedTokenCache, identity.UserID)
	delete(a.tokenHashCache, strings.ToLower(identity.UserLogin))
	delete(a.sessionUser, sessionID)
	a.mu.Unlock()
	a.clearIdentityCookies(w)

	log.Printf("cleared encrypted token from memory+db: user_id=%s login=%s", identity.UserID, identity.UserLogin)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "memory cache and database cleared",
		"user_id":    identity.UserID,
		"user_login": identity.UserLogin,
	})
}
