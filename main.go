// Share a folder on the local network. The host UI is localhost-only.
//
// Build a single executable (pages are embedded):
//
//	go build -o localServe .
package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed pages/*.html
var pageFiles embed.FS

const (
	defaultPort            = 8765
	downloadTokenSeconds   = 60 * 60
	passwordIterations     = 120_000
	maximumRequestBodySize = 1 << 20
)

type application struct {
	port           int
	stateLock      sync.Mutex
	directory      string
	passwordDigest []byte
	passwordSalt   []byte
	signingKey     []byte
	sharing        bool
}

type sharedFile struct {
	name string
	size int64
}

func newApplication(port int) *application {
	return &application{
		port:       port,
		signingKey: randomBytes(32),
	}
}

func randomBytes(size int) []byte {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return buffer
}

func digestPassword(password string, salt []byte) []byte {
	digest, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, sha256.Size)
	if err != nil {
		return nil
	}
	return digest
}

func (application *application) passwordMatches(password string) bool {
	application.stateLock.Lock()
	salt := application.passwordSalt
	expected := application.passwordDigest
	sharing := application.sharing
	application.stateLock.Unlock()
	if !sharing || salt == nil || expected == nil {
		return false
	}
	actual := digestPassword(password, salt)
	return hmac.Equal(actual, expected)
}

func safeSharedFile(directory, filename string) (string, bool) {
	if directory == "" || filename == "" {
		return "", false
	}
	if filename != filepath.Base(filename) || filename == "." || filename == ".." {
		return "", false
	}
	if strings.HasPrefix(filename, ".") {
		return "", false
	}
	folder, err := filepath.Abs(directory)
	if err != nil {
		return "", false
	}
	resolvedFolder, err := filepath.EvalSymlinks(folder)
	if err != nil {
		return "", false
	}
	resolvedFile, err := filepath.EvalSymlinks(filepath.Join(resolvedFolder, filename))
	if err != nil {
		return "", false
	}
	if filepath.Dir(resolvedFile) != resolvedFolder {
		return "", false
	}
	info, err := os.Stat(resolvedFile)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	return resolvedFile, true
}

func listedFiles(directory string) ([]sharedFile, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	files := make([]sharedFile, 0)
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		info, statErr := os.Stat(filepath.Join(directory, name))
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		files = append(files, sharedFile{name: name, size: info.Size()})
	}
	sort.Slice(files, func(i, j int) bool {
		return strings.ToLower(files[i].name) < strings.ToLower(files[j].name)
	})
	return files, nil
}

func downloadToken(filename string, signingKey []byte, now int64) string {
	expiresAt := now + downloadTokenSeconds
	payload := fmt.Sprintf("%s:%d", filename, expiresAt)
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(payload))
	return fmt.Sprintf("%d.%s", expiresAt, hex.EncodeToString(mac.Sum(nil)))
}

func tokenIsValid(filename, token string, signingKey []byte, now int64) bool {
	expiresText, signature, found := strings.Cut(token, ".")
	if !found {
		return false
	}
	expiresAt, err := strconv.ParseInt(expiresText, 10, 64)
	if err != nil {
		return false
	}
	if expiresAt < now {
		return false
	}
	payload := fmt.Sprintf("%s:%d", filename, expiresAt)
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}

func readableSize(size int64) string {
	value := float64(size)
	for _, unit := range []string{"B", "KB", "MB", "GB", "TB"} {
		if value < 1024 || unit == "TB" {
			if unit == "B" {
				return fmt.Sprintf("%d %s", int64(value), unit)
			}
			return fmt.Sprintf("%.1f %s", value, unit)
		}
		value /= 1024
	}
	return fmt.Sprintf("%d B", size)
}

func expandUser(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, path[2:])
}

func resolveDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(expandUser(strings.TrimSpace(path)))
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("not a directory")
	}
	return resolved, nil
}

// ponytail: folder picker is macOS osascript only; other systems paste a path. Upgrade path is a native dialog per OS.
func pickFolderNative() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	command := exec.Command("osascript", "-e", `POSIX path of (choose folder with prompt "Choose a folder to share")`)
	output, err := command.Output()
	if err != nil {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(string(output)), "/")
}

func localIPAddresses() []string {
	probe, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return []string{"127.0.0.1"}
	}
	defer probe.Close()
	address, ok := probe.LocalAddr().(*net.UDPAddr)
	if !ok || address.IP == nil {
		return []string{"127.0.0.1"}
	}
	return []string{address.IP.String()}
}

func shareLinks(port int) []string {
	addresses := localIPAddresses()
	links := make([]string, 0, len(addresses))
	for _, address := range addresses {
		links = append(links, fmt.Sprintf("http://%s:%d", address, port))
	}
	return links
}

func loadPage(name string) string {
	data, err := pageFiles.ReadFile("pages/" + name)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func escapeHTML(text string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	).Replace(text)
}

func clientIsLocal(request *http.Request) bool {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func sendHTML(response http.ResponseWriter, body string, status int) {
	payload := []byte(body)
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(payload)
}

func sendJSON(response http.ResponseWriter, data any, status int) {
	payload, err := json.Marshal(data)
	if err != nil {
		payload = []byte(`{"error":"internal error"}`)
		status = http.StatusInternalServerError
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(payload)
}

func readJSONBody(request *http.Request) (map[string]any, error) {
	request.Body = http.MaxBytesReader(nil, request.Body, maximumRequestBodySize)
	decoder := json.NewDecoder(request.Body)
	var body map[string]any
	err := decoder.Decode(&body)
	if errors.Is(err, io.EOF) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if body == nil {
		return map[string]any{}, nil
	}
	return body, nil
}

func readFormBody(request *http.Request) (map[string]string, error) {
	request.Body = http.MaxBytesReader(nil, request.Body, maximumRequestBodySize)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, err
	}
	form := make(map[string]string, len(values))
	for key, items := range values {
		if len(items) > 0 {
			form[key] = items[0]
		}
	}
	return form, nil
}

func stringField(body map[string]any, key string) string {
	value, _ := body[key].(string)
	return value
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	copied := value
	return &copied
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusResponseWriter) WriteHeader(status int) {
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (application *application) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	recorder := &statusResponseWriter{ResponseWriter: response, status: http.StatusOK}
	switch request.Method {
	case http.MethodGet:
		application.handleGet(recorder, request)
	case http.MethodPost:
		application.handlePost(recorder, request)
	default:
		sendHTML(recorder, "<h1>Not found</h1>", http.StatusNotFound)
	}
	log.Printf("%s - %s %s %d", request.RemoteAddr, request.Method, request.URL.RequestURI(), recorder.status)
}

func (application *application) handleGet(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/admin":
		if !clientIsLocal(request) {
			sendHTML(response, "<h1>Forbidden</h1>", http.StatusForbidden)
			return
		}
		sendHTML(response, loadPage("admin.html"), http.StatusOK)
	case "/admin/api/status":
		application.handleStatus(response, request)
	case "/download":
		application.handleDownload(response, request)
	case "/":
		page := strings.ReplaceAll(loadPage("login.html"), "{{error}}", "")
		sendHTML(response, page, http.StatusOK)
	default:
		sendHTML(response, "<h1>Not found</h1>", http.StatusNotFound)
	}
}

func (application *application) handleStatus(response http.ResponseWriter, request *http.Request) {
	if !clientIsLocal(request) {
		sendJSON(response, map[string]string{"error": "forbidden"}, http.StatusForbidden)
		return
	}
	application.stateLock.Lock()
	directory := application.directory
	sharing := application.sharing
	application.stateLock.Unlock()

	fileCount := 0
	if sharing && directory != "" {
		files, err := listedFiles(directory)
		if err == nil {
			fileCount = len(files)
		}
	}
	links := []string{}
	if sharing {
		links = shareLinks(application.port)
	}
	sendJSON(response, map[string]any{
		"sharing":    sharing,
		"directory":  optionalString(directory),
		"file_count": fileCount,
		"links":      links,
		"admin":      fmt.Sprintf("http://127.0.0.1:%d/admin", application.port),
	}, http.StatusOK)
}

func (application *application) handleDownload(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	filename := query.Get("file")
	token := query.Get("token")
	application.stateLock.Lock()
	directory := application.directory
	signingKey := application.signingKey
	sharing := application.sharing
	application.stateLock.Unlock()

	if !sharing || !tokenIsValid(filename, token, signingKey, time.Now().Unix()) {
		page := strings.ReplaceAll(loadPage("login.html"), "{{error}}", "Enter the password to download files.")
		sendHTML(response, page, http.StatusUnauthorized)
		return
	}
	path, ok := safeSharedFile(directory, filename)
	if !ok {
		sendHTML(response, "<h1>Not found</h1>", http.StatusNotFound)
		return
	}
	sendFile(response, path)
}

func (application *application) handlePost(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/admin/api/pick-folder":
		if !clientIsLocal(request) {
			sendJSON(response, map[string]string{"error": "forbidden"}, http.StatusForbidden)
			return
		}
		chosen := pickFolderNative()
		sendJSON(response, map[string]any{"path": optionalString(chosen)}, http.StatusOK)
	case "/admin/api/share":
		application.handleShare(response, request)
	case "/admin/api/stop":
		application.handleStop(response, request)
	case "/login":
		application.handleLogin(response, request)
	default:
		sendHTML(response, "<h1>Not found</h1>", http.StatusNotFound)
	}
}

func (application *application) handleShare(response http.ResponseWriter, request *http.Request) {
	if !clientIsLocal(request) {
		sendJSON(response, map[string]string{"error": "forbidden"}, http.StatusForbidden)
		return
	}
	body, err := readJSONBody(request)
	if err != nil {
		sendJSON(response, map[string]string{"error": "Invalid request."}, http.StatusBadRequest)
		return
	}
	directory := strings.TrimSpace(stringField(body, "directory"))
	password := stringField(body, "password")
	resolved, err := resolveDirectory(directory)
	if directory == "" || err != nil {
		sendJSON(response, map[string]string{"error": "Choose an existing folder."}, http.StatusBadRequest)
		return
	}
	if password == "" {
		sendJSON(response, map[string]string{"error": "Set a password for guests."}, http.StatusBadRequest)
		return
	}
	salt := randomBytes(16)
	application.stateLock.Lock()
	application.directory = resolved
	application.passwordSalt = salt
	application.passwordDigest = digestPassword(password, salt)
	application.signingKey = randomBytes(32)
	application.sharing = true
	application.stateLock.Unlock()

	fileCount := 0
	files, listErr := listedFiles(resolved)
	if listErr == nil {
		fileCount = len(files)
	}
	sendJSON(response, map[string]any{
		"ok":         true,
		"directory":  resolved,
		"links":      shareLinks(application.port),
		"file_count": fileCount,
	}, http.StatusOK)
}

func (application *application) handleStop(response http.ResponseWriter, request *http.Request) {
	if !clientIsLocal(request) {
		sendJSON(response, map[string]string{"error": "forbidden"}, http.StatusForbidden)
		return
	}
	application.stateLock.Lock()
	application.directory = ""
	application.passwordDigest = nil
	application.passwordSalt = nil
	application.signingKey = randomBytes(32)
	application.sharing = false
	application.stateLock.Unlock()
	sendJSON(response, map[string]any{"ok": true}, http.StatusOK)
}

func (application *application) handleLogin(response http.ResponseWriter, request *http.Request) {
	form, err := readFormBody(request)
	if err != nil {
		sendHTML(response, "<h1>Not found</h1>", http.StatusBadRequest)
		return
	}
	if !application.passwordMatches(form["password"]) {
		page := strings.ReplaceAll(loadPage("login.html"), "{{error}}", "Wrong password.")
		sendHTML(response, page, http.StatusUnauthorized)
		return
	}
	page := application.filesPage()
	sendHTML(response, page, http.StatusOK)
}

func (application *application) filesPage() string {
	application.stateLock.Lock()
	directory := application.directory
	signingKey := application.signingKey
	application.stateLock.Unlock()

	var rows strings.Builder
	files, err := listedFiles(directory)
	if err == nil {
		now := time.Now().Unix()
		for _, file := range files {
			token := downloadToken(file.name, signingKey, now)
			href := "/download?" + url.Values{
				"file":  {file.name},
				"token": {token},
			}.Encode()
			name := escapeHTML(file.name)
			fmt.Fprintf(&rows, `<li><a href="%s" download="%s">%s</a><span>%s</span></li>`,
				escapeHTML(href), name, name, readableSize(file.size))
		}
	}
	filesHTML := rows.String()
	if filesHTML == "" {
		filesHTML = "<li class='empty'>No files in this folder.</li>"
	}
	page := strings.ReplaceAll(loadPage("files.html"), "{{folder}}", escapeHTML(filepath.Base(directory)))
	return strings.ReplaceAll(page, "{{files}}", filesHTML)
}

func sendFile(response http.ResponseWriter, path string) {
	file, err := os.Open(path)
	if err != nil {
		sendHTML(response, "<h1>Not found</h1>", http.StatusNotFound)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		sendHTML(response, "<h1>Not found</h1>", http.StatusNotFound)
		return
	}
	contentType := mime.TypeByExtension(filepath.Ext(path))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	response.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(filepath.Base(path)))
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = io.Copy(response, file)
}

func openBrowser(target string) {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	_ = command.Start()
}

func run(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return err
	}
	adminURL := fmt.Sprintf("http://127.0.0.1:%d/admin", port)
	fmt.Printf("Host panel: %s\n", adminURL)
	fmt.Println("Guest link appears in the host panel after you start sharing.")

	httpServer := &http.Server{
		Handler:           newApplication(port),
		ReadHeaderTimeout: 10 * time.Second,
	}
	stopSignals := make(chan os.Signal, 1)
	signal.Notify(stopSignals, os.Interrupt)
	go func() {
		<-stopSignals
		fmt.Println("\nStopped.")
		_ = httpServer.Close()
	}()
	go func() {
		time.Sleep(400 * time.Millisecond)
		openBrowser(adminURL)
	}()

	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func main() {
	port := defaultPort
	if len(os.Args) > 1 {
		chosenPort, err := strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		port = chosenPort
	}
	if err := run(port); err != nil {
		log.Fatal(err)
	}
}
