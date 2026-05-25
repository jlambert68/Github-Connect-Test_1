package main

import (
	"path/filepath"
	"testing"
)

func newTestApp(t *testing.T) *app {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "auth_tokens_test.db")
	db, err := openSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("openSQLiteDB() error: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	return &app{
		sessionUser:         make(map[string]sessionIdentity),
		encryptedTokenCache: make(map[string]string),
		tokenHashCache:      make(map[string]string),
		db:                  db,
		encryptionKey:       deriveEncryptionKey("unit-test-key"),
	}
}
