package main

import (
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeSharedFileAndDownloadToken(t *testing.T) {
	folder := t.TempDir()
	inside := filepath.Join(folder, "notes.txt")
	if err := os.WriteFile(inside, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, ".secret"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}

	resolved, ok := safeSharedFile(folder, "notes.txt")
	if !ok {
		t.Fatal("expected notes.txt to be shared")
	}
	expected, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != expected {
		t.Fatalf("resolved %s, want %s", resolved, expected)
	}
	if _, ok := safeSharedFile(folder, "../notes.txt"); ok {
		t.Fatal("parent path was allowed")
	}
	if _, ok := safeSharedFile(folder, "nested/notes.txt"); ok {
		t.Fatal("nested path was allowed")
	}
	if _, ok := safeSharedFile(folder, ".secret"); ok {
		t.Fatal("hidden file was allowed")
	}
	if _, ok := safeSharedFile(folder, "missing.txt"); ok {
		t.Fatal("missing file was allowed")
	}

	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(folder, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if _, ok := safeSharedFile(folder, "link.txt"); ok {
		t.Fatal("symlink escaped the shared folder")
	}

	key := []byte("test-signing-key")
	token := downloadToken("notes.txt", key, 1_000_000)
	if !tokenIsValid("notes.txt", token, key, 1_000_000) {
		t.Fatal("fresh token was rejected")
	}
	if tokenIsValid("other.txt", token, key, 1_000_000) {
		t.Fatal("token worked for a different file")
	}
	if tokenIsValid("notes.txt", token, key, 1_000_000+60*60+1) {
		t.Fatal("expired token was accepted")
	}
	if tokenIsValid("notes.txt", "nope", key, 1_000_000) {
		t.Fatal("garbage token was accepted")
	}
}

func TestShareLoginAndDownload(t *testing.T) {
	folder := t.TempDir()
	if err := os.WriteFile(filepath.Join(folder, "notes.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := newApplication(8765)

	shareBody := `{"directory":"` + folder + `","password":"secret"}`
	share := httptest.NewRequest(http.MethodPost, "/admin/api/share", strings.NewReader(shareBody))
	share.RemoteAddr = "127.0.0.1:1234"
	share.Header.Set("Content-Type", "application/json")
	shareRecorder := httptest.NewRecorder()
	app.ServeHTTP(shareRecorder, share)
	if shareRecorder.Code != http.StatusOK {
		t.Fatalf("share status %d: %s", shareRecorder.Code, shareRecorder.Body.String())
	}

	guestAdmin := httptest.NewRequest(http.MethodGet, "/admin", nil)
	guestAdmin.RemoteAddr = "192.168.1.20:1234"
	guestAdminRecorder := httptest.NewRecorder()
	app.ServeHTTP(guestAdminRecorder, guestAdmin)
	if guestAdminRecorder.Code != http.StatusForbidden {
		t.Fatalf("guest admin status %d", guestAdminRecorder.Code)
	}

	wrong := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("password=nope"))
	wrong.RemoteAddr = "192.168.1.20:9"
	wrong.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongRecorder := httptest.NewRecorder()
	app.ServeHTTP(wrongRecorder, wrong)
	if wrongRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status %d", wrongRecorder.Code)
	}
	if strings.Contains(wrongRecorder.Body.String(), "notes.txt") {
		t.Fatal("wrong password revealed a file")
	}

	login := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("password=secret"))
	login.RemoteAddr = "192.168.1.20:9"
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRecorder := httptest.NewRecorder()
	app.ServeHTTP(loginRecorder, login)
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status %d", loginRecorder.Code)
	}
	body := loginRecorder.Body.String()
	marker := `href="`
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("file list missing download link: %s", body)
	}
	rest := body[start+len(marker):]
	end := strings.Index(rest, `"`)
	href := html.UnescapeString(rest[:end])

	download := httptest.NewRequest(http.MethodGet, href, nil)
	download.RemoteAddr = "192.168.1.20:9"
	downloadRecorder := httptest.NewRecorder()
	app.ServeHTTP(downloadRecorder, download)
	if downloadRecorder.Code != http.StatusOK {
		t.Fatalf("download status %d: %s", downloadRecorder.Code, downloadRecorder.Body.String())
	}
	if downloadRecorder.Body.String() != "hello" {
		t.Fatalf("download body %q", downloadRecorder.Body.String())
	}
	disposition := downloadRecorder.Header().Get("Content-Disposition")
	if !strings.Contains(disposition, "attachment;") {
		t.Fatalf("disposition %q", disposition)
	}
}
