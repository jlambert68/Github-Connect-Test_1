package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// deriveEncryptionKey converts the env-provided secret into a fixed 32-byte key.
// We intentionally hash the raw secret so any length input can be used consistently.
func deriveEncryptionKey(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// hashUserLoginAndToken creates the user+token binding checksum used in cache/DB verification.
// Login is normalized to lowercase/trimmed to make comparisons deterministic.
func hashUserLoginAndToken(userLogin, token string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(userLogin)) + token))
	return hex.EncodeToString(sum[:])
}

// openSQLiteDB opens SQLite and ensures required auth_tokens schema exists.
func openSQLiteDB(filePath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", filePath)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	ddl := `
CREATE TABLE IF NOT EXISTS auth_tokens (
  user_id TEXT PRIMARY KEY,
  user_login TEXT NOT NULL,
  encrypted_token TEXT NOT NULL,
  token_hash TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);`
	if _, err := db.Exec(ddl); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Backward-compatible migration for older DBs created before token_hash existed.
	_, _ = db.Exec(`ALTER TABLE auth_tokens ADD COLUMN token_hash TEXT NOT NULL DEFAULT ''`)
	return db, nil
}

// upsertEncryptedTokenInDB stores/updates one row per GitHub user id.
func (a *app) upsertEncryptedTokenInDB(userID, userLogin, encryptedToken, tokenHash string) error {
	_, err := a.db.Exec(
		`INSERT INTO auth_tokens(user_id, user_login, encrypted_token, token_hash, updated_at)
		 VALUES(?, ?, ?, ?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET
		   user_login = excluded.user_login,
		   encrypted_token = excluded.encrypted_token,
		   token_hash = excluded.token_hash,
		   updated_at = excluded.updated_at`,
		userID,
		userLogin,
		encryptedToken,
		tokenHash,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

// getEncryptedTokenFromDB loads encrypted token material for a user id.
// found=false is returned when row does not exist.
func (a *app) getEncryptedTokenFromDB(userID string) (encryptedToken string, tokenHash string, userLogin string, found bool, err error) {
	var encrypted string
	var hash string
	var login string
	err = a.db.QueryRow(`SELECT encrypted_token, token_hash, user_login FROM auth_tokens WHERE user_id = ?`, userID).Scan(&encrypted, &hash, &login)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	return encrypted, strings.ToLower(strings.TrimSpace(hash)), strings.TrimSpace(login), true, nil
}

// getSingleStoredIdentityFromDB returns identity only when exactly one token row exists.
// This avoids ambiguous auto-login when multiple users are stored in the same backend.
func (a *app) getSingleStoredIdentityFromDB() (sessionIdentity, bool, error) {
	rows, err := a.db.Query(`SELECT user_id, user_login FROM auth_tokens ORDER BY updated_at DESC LIMIT 2`)
	if err != nil {
		return sessionIdentity{}, false, err
	}
	defer rows.Close()

	identities := make([]sessionIdentity, 0, 2)
	for rows.Next() {
		var userID string
		var userLogin string
		if scanErr := rows.Scan(&userID, &userLogin); scanErr != nil {
			return sessionIdentity{}, false, scanErr
		}
		userID = strings.TrimSpace(userID)
		userLogin = strings.TrimSpace(userLogin)
		if userID == "" || userLogin == "" {
			continue
		}
		identities = append(identities, sessionIdentity{
			UserID:    userID,
			UserLogin: userLogin,
		})
	}
	if err := rows.Err(); err != nil {
		return sessionIdentity{}, false, err
	}
	if len(identities) == 1 {
		return identities[0], true, nil
	}
	return sessionIdentity{}, false, nil
}

// deleteEncryptedTokenFromDB removes persisted token material for one user id.
func (a *app) deleteEncryptedTokenFromDB(userID string) error {
	_, err := a.db.Exec(`DELETE FROM auth_tokens WHERE user_id = ?`, userID)
	return err
}

// encryptToken encrypts plaintext token using AES-GCM and returns base64(nonce|ciphertext).
func (a *app) encryptToken(plain string) (string, error) {
	block, err := aes.NewCipher(a.encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plain), nil)
	combined := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

// decryptToken reverses encryptToken and returns the plaintext access token.
func (a *app) decryptToken(encrypted string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(a.encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("encrypted token payload too short")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// getDecryptedTokenForUser is the central token retrieval/verification path used by all outbound calls.
//
// Order of operations:
// 1) Try in-memory encrypted token + hash.
// 2) If missing, load from SQLite and warm caches.
// 3) Decrypt token.
// 4) Recompute hash(userLogin + token) and compare with stored hash.
// Only a fully verified token is returned.
func (a *app) getDecryptedTokenForUser(ctx context.Context, userID, userLogin string) (string, error) {
	a.mu.RLock()
	encrypted, hasEncrypted := a.encryptedTokenCache[userID]
	loginKey := strings.ToLower(strings.TrimSpace(userLogin))
	cachedHash, hasHash := a.tokenHashCache[loginKey]
	a.mu.RUnlock()
	if !hasEncrypted || !hasHash {
		// Cache miss: pull encrypted material from SQLite and repopulate in-memory caches.
		dbEncrypted, dbHash, dbUserLogin, found, err := a.getEncryptedTokenFromDB(userID)
		if err != nil {
			return "", err
		}
		if !found {
			return "", fmt.Errorf("encrypted token not found for user_id=%s", userID)
		}
		if dbUserLogin != "" && !strings.EqualFold(dbUserLogin, userLogin) {
			// Prevent accidental cross-user token usage if user/login pair does not match.
			return "", fmt.Errorf("user login mismatch for user_id=%s: session=%q db=%q", userID, userLogin, dbUserLogin)
		}
		encrypted = dbEncrypted
		cachedHash = dbHash
		a.mu.Lock()
		a.encryptedTokenCache[userID] = dbEncrypted
		a.tokenHashCache[loginKey] = dbHash
		a.mu.Unlock()
		log.Printf("loaded encrypted token+hash from sqlite into memory cache: user_id=%s login=%s", userID, userLogin)
	}
	token, err := a.decryptToken(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt token for user_id=%s: %w", userID, err)
	}

	expectedHash := hashUserLoginAndToken(userLogin, token)
	if strings.TrimSpace(strings.ToLower(cachedHash)) == "" {
		return "", fmt.Errorf("token hash missing for user_id=%s login=%s", userID, userLogin)
	}
	if expectedHash != strings.TrimSpace(strings.ToLower(cachedHash)) {
		// Final guard: token must be cryptographically tied to expected user login.
		return "", fmt.Errorf("token hash verification failed for user_id=%s login=%s", userID, userLogin)
	}

	_ = ctx
	return token, nil
}

// ensureSessionID returns existing session cookie or creates one if missing.
func (a *app) ensureSessionID(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("session_id"); err == nil && c.Value != "" {
		return c.Value
	}

	sessionID, err := randomHex(24)
	if err != nil {
		sessionID = fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})
	return sessionID
}

// getSessionID reads current backend session id from cookie.
func (a *app) getSessionID(r *http.Request) (string, bool) {
	c, err := r.Cookie("session_id")
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// getOrRestoreSessionIdentity is a convenience wrapper using session id from cookies.
func (a *app) getOrRestoreSessionIdentity(r *http.Request) (sessionIdentity, bool) {
	sessionID, ok := a.getSessionID(r)
	if !ok {
		return sessionIdentity{}, false
	}
	return a.getOrRestoreSessionIdentityWithSessionID(sessionID, r)
}

// getOrRestoreSessionIdentityWithSessionID restores identity in this strict order:
// 1) in-memory session map
// 2) auth identity cookies
//
// Important security rule: without a valid signed identity cookie, we do NOT restore
// identity from DB. This prevents one browser/session from inheriting another user's token.
func (a *app) getOrRestoreSessionIdentityWithSessionID(sessionID string, r *http.Request) (sessionIdentity, bool) {
	if strings.TrimSpace(sessionID) == "" {
		return sessionIdentity{}, false
	}

	a.mu.RLock()
	identity, has := a.sessionUser[sessionID]
	a.mu.RUnlock()
	if has {
		// Fast path: already bound to this session in memory.
		return identity, true
	}

	userIDCookie, err1 := r.Cookie("auth_user_id")
	userLoginCookie, err2 := r.Cookie("auth_user_login")
	userSigCookie, err3 := r.Cookie("auth_user_sig")
	if err1 == nil && err2 == nil && err3 == nil {
		userID := strings.TrimSpace(userIDCookie.Value)
		userLogin := strings.TrimSpace(userLoginCookie.Value)
		if userID != "" && userLogin != "" {
			userName := ""
			if c, err := r.Cookie("auth_user_name"); err == nil {
				userName = strings.TrimSpace(c.Value)
			}
			identity = sessionIdentity{
				UserID:    userID,
				UserLogin: userLogin,
				UserName:  userName,
			}
			expectedSig := a.identitySignature(identity)
			if !hmac.Equal([]byte(strings.TrimSpace(userSigCookie.Value)), []byte(expectedSig)) {
				log.Printf("identity cookie signature mismatch: session_id=%s user_id=%s login=%s", sessionID, userID, userLogin)
				return sessionIdentity{}, false
			}

			a.mu.Lock()
			a.sessionUser[sessionID] = identity
			a.mu.Unlock()
			// Persist restored cookie identity in session map for future requests.
			log.Printf("restored session identity from cookies: session_id=%s user_id=%s login=%s", sessionID, userID, userLogin)
			return identity, true
		}
	}

	return sessionIdentity{}, false
}

// setIdentityCookies writes stable identity cookies used for session restoration.
func (a *app) setIdentityCookies(w http.ResponseWriter, identity sessionIdentity) {
	maxAge := 24 * 3600
	signature := a.identitySignature(identity)
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_user_id",
		Value:    identity.UserID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_user_login",
		Value:    identity.UserLogin,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_user_name",
		Value:    identity.UserName,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_user_sig",
		Value:    signature,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// clearIdentityCookies removes identity cookies during full logout/clear-all.
func (a *app) clearIdentityCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "auth_user_id", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "auth_user_login", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "auth_user_name", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "auth_user_sig", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (a *app) identitySignature(identity sessionIdentity) string {
	mac := hmac.New(sha256.New, a.encryptionKey)
	_, _ = mac.Write([]byte(strings.TrimSpace(identity.UserID)))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(identity.UserLogin))))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(strings.TrimSpace(identity.UserName)))
	return hex.EncodeToString(mac.Sum(nil))
}
