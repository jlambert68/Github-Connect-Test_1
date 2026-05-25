package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHashUserLoginAndToken_IsCaseInsensitiveForLogin(t *testing.T) {
	token := "token-123"
	h1 := hashUserLoginAndToken("GithubForTemplates", token)
	h2 := hashUserLoginAndToken("githubfortemplates", token)

	if h1 != h2 {
		t.Fatalf("expected equal hashes for login case variants; got %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("expected sha256 hex length 64, got %d", len(h1))
	}
}

func TestGetDecryptedTokenForUser_LoadsFromDBAndCaches(t *testing.T) {
	a := newTestApp(t)
	userID := "1001"
	userLogin := "githubfortemplates"
	token := "gho_example_token"

	encrypted, err := a.encryptToken(token)
	if err != nil {
		t.Fatalf("encryptToken() error: %v", err)
	}
	hash := hashUserLoginAndToken(userLogin, token)
	if err := a.upsertEncryptedTokenInDB(userID, userLogin, encrypted, hash); err != nil {
		t.Fatalf("upsertEncryptedTokenInDB() error: %v", err)
	}

	got, err := a.getDecryptedTokenForUser(context.Background(), userID, strings.ToUpper(userLogin))
	if err != nil {
		t.Fatalf("getDecryptedTokenForUser() error: %v", err)
	}
	if got != token {
		t.Fatalf("got token %q, want %q", got, token)
	}

	loginKey := strings.ToLower(userLogin)
	if a.encryptedTokenCache[userID] == "" {
		t.Fatalf("expected encrypted token to be loaded into memory cache for user_id=%s", userID)
	}
	if a.tokenHashCache[loginKey] == "" {
		t.Fatalf("expected token hash to be loaded into memory cache for login=%s", loginKey)
	}

	if err := a.deleteEncryptedTokenFromDB(userID); err != nil {
		t.Fatalf("deleteEncryptedTokenFromDB() error: %v", err)
	}

	got2, err := a.getDecryptedTokenForUser(context.Background(), userID, userLogin)
	if err != nil {
		t.Fatalf("getDecryptedTokenForUser() from cache error: %v", err)
	}
	if got2 != token {
		t.Fatalf("got token %q from cache, want %q", got2, token)
	}
}

func TestGetDecryptedTokenForUser_FailsOnHashMismatch(t *testing.T) {
	a := newTestApp(t)
	userID := "1002"
	userLogin := "githubfortemplates"
	token := "gho_example_token_2"

	encrypted, err := a.encryptToken(token)
	if err != nil {
		t.Fatalf("encryptToken() error: %v", err)
	}
	if err := a.upsertEncryptedTokenInDB(userID, userLogin, encrypted, "deadbeef"); err != nil {
		t.Fatalf("upsertEncryptedTokenInDB() error: %v", err)
	}

	_, err = a.getDecryptedTokenForUser(context.Background(), userID, userLogin)
	if err == nil {
		t.Fatalf("expected hash verification error, got nil")
	}
	if !strings.Contains(err.Error(), "token hash verification failed") {
		t.Fatalf("expected hash verification error, got: %v", err)
	}
}

func TestGetSingleStoredIdentityFromDB(t *testing.T) {
	a := newTestApp(t)
	token := "gho_identity_test"

	enc1, err := a.encryptToken(token)
	if err != nil {
		t.Fatalf("encryptToken() error: %v", err)
	}
	hash1 := hashUserLoginAndToken("user1", token)
	if err := a.upsertEncryptedTokenInDB("1", "user1", enc1, hash1); err != nil {
		t.Fatalf("upsert #1 error: %v", err)
	}

	identity, found, err := a.getSingleStoredIdentityFromDB()
	if err != nil {
		t.Fatalf("getSingleStoredIdentityFromDB() error: %v", err)
	}
	if !found {
		t.Fatalf("expected identity to be found")
	}
	if identity.UserID != "1" || identity.UserLogin != "user1" {
		t.Fatalf("unexpected identity: %+v", identity)
	}

	enc2, err := a.encryptToken(token + "-2")
	if err != nil {
		t.Fatalf("encryptToken() error: %v", err)
	}
	hash2 := hashUserLoginAndToken("user2", token+"-2")
	if err := a.upsertEncryptedTokenInDB("2", "user2", enc2, hash2); err != nil {
		t.Fatalf("upsert #2 error: %v", err)
	}

	_, found, err = a.getSingleStoredIdentityFromDB()
	if err != nil {
		t.Fatalf("getSingleStoredIdentityFromDB() error: %v", err)
	}
	if found {
		t.Fatalf("expected no single identity when multiple users exist")
	}
}

func TestGetOrRestoreSessionIdentityWithSessionID_FromCookies(t *testing.T) {
	a := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	identity := sessionIdentity{
		UserID:    "42",
		UserLogin: "cookie-user",
		UserName:  "Cookie User",
	}
	sig := a.identitySignature(identity)
	req.AddCookie(&http.Cookie{Name: "auth_user_id", Value: "42"})
	req.AddCookie(&http.Cookie{Name: "auth_user_login", Value: "cookie-user"})
	req.AddCookie(&http.Cookie{Name: "auth_user_name", Value: "Cookie User"})
	req.AddCookie(&http.Cookie{Name: "auth_user_sig", Value: sig})

	identity, ok := a.getOrRestoreSessionIdentityWithSessionID("session-1", req)
	if !ok {
		t.Fatalf("expected identity from cookies")
	}
	if identity.UserID != "42" || identity.UserLogin != "cookie-user" || identity.UserName != "Cookie User" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
}

func TestGetOrRestoreSessionIdentityWithSessionID_RejectsInvalidSignature(t *testing.T) {
	a := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_user_id", Value: "42"})
	req.AddCookie(&http.Cookie{Name: "auth_user_login", Value: "cookie-user"})
	req.AddCookie(&http.Cookie{Name: "auth_user_name", Value: "Cookie User"})
	req.AddCookie(&http.Cookie{Name: "auth_user_sig", Value: "bad-signature"})

	_, ok := a.getOrRestoreSessionIdentityWithSessionID("session-2", req)
	if ok {
		t.Fatalf("expected invalid signature to be rejected")
	}
}

func TestGetOrRestoreSessionIdentityWithSessionID_NoDBFallbackWithoutCookies(t *testing.T) {
	a := newTestApp(t)
	userID := "77"
	userLogin := "db-user"
	token := "gho_db_fallback"

	encrypted, err := a.encryptToken(token)
	if err != nil {
		t.Fatalf("encryptToken() error: %v", err)
	}
	hash := hashUserLoginAndToken(userLogin, token)
	if err := a.upsertEncryptedTokenInDB(userID, userLogin, encrypted, hash); err != nil {
		t.Fatalf("upsertEncryptedTokenInDB() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, ok := a.getOrRestoreSessionIdentityWithSessionID("session-db", req)
	if ok {
		t.Fatalf("expected no restore without valid identity cookies")
	}
}
