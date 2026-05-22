package main

import (
	"archive/zip"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const (
	maxPDFBytes     = 25 << 20
	maxRequestBytes = 100 << 20
	defaultAddr     = ":8010"
	defaultDBURL    = "host=/tmp/url-generator-postgres port=5432 user=url_generator password=url_generator_password dbname=url_generator sslmode=disable"
	sessionCookie   = "url_generator_session"
	passwordIters   = 210000
)

var (
	filesDir = filepath.Join("storage", "files")
	metaDir  = filepath.Join("storage", "meta")
	sessions = sessionStore{values: map[string]time.Time{}}
	authDB   *sql.DB
	logins   = newLoginLimiter(5, 10*time.Minute)
)

type fileMeta struct {
	ID           string    `json:"id"`
	File         string    `json:"file"`
	OriginalName string    `json:"original_name"`
	Size         int64     `json:"size"`
	CreatedAt    time.Time `json:"created_at"`
}

type pageData struct {
	Title       string
	Active      string
	Error       string
	Login       bool
	Uploads     []uploadLink
	Files       []uploadedFile
	FileName    string
	ID          string
	MaxUploadMB int
	MaxPDFMB    int
	Wide        bool
}

type uploadLink struct {
	Name string
	URL  string
}

type uploadedFile struct {
	Name      string
	URL       string
	Download  string
	Size      string
	CreatedAt string
}

type sessionStore struct {
	mu     sync.Mutex
	values map[string]time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	attempts map[string]loginAttempt
}

type loginAttempt struct {
	count     int
	expiresAt time.Time
}

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="ru">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>{{.Title}}</title>
	<link rel="stylesheet" href="/assets/styles.css">
</head>
<body>
	<main class="page{{if .Wide}} page-public{{end}}">
		{{if .Login}}
			<section class="login-screen">
				<div class="login-panel">
					<div class="login-heading">
						<h1>PDF URL Generator</h1>
						<p>Вход в панель управления</p>
					</div>

					{{if .Error}}<div class="alert alert-error" role="alert">{{.Error}}</div>{{end}}

					<form action="/login" method="post" class="form form-login">
						<div class="field">
							<label for="username">Логин</label>
							<input id="username" name="username" type="text" autocomplete="username" required>
						</div>

						<div class="field">
							<label for="password">Пароль</label>
							<input id="password" name="password" type="password" autocomplete="current-password" required>
						</div>

						<button class="btn btn-primary" type="submit">Войти</button>
					</form>
				</div>
			</section>
		{{else if .ID}}
			<section class="public-pdf">
				<div class="public-pdf-actions">
					<a class="btn btn-primary" href="/p/{{.ID}}/download">Скачать PDF</a>
				</div>
				<div class="pdf-viewer">
					<iframe title="{{.FileName}}" src="/p/{{.ID}}/inline#toolbar=0&navpanes=0&scrollbar=0&view=FitH"></iframe>
				</div>
			</section>
		{{else}}
			<div class="app-layout">
				<aside class="sidebar">
					<div class="brand">
						<strong>PDF URL Generator</strong>
					</div>
					<nav class="sidebar-nav">
						<a class="{{if eq .Active "upload"}}active{{end}}" href="/">Загрузить</a>
						<a class="{{if eq .Active "uploaded"}}active{{end}}" href="/uploads">Загруженные</a>
						<a href="/logout">Выйти</a>
					</nav>
				</aside>

				<section class="workspace">
					{{if .Uploads}}
						<header class="page-header">
							<h1>Готово</h1>
						</header>

						<div class="alert alert-success">
							<strong>Создано ссылок: {{len .Uploads}}</strong>
						</div>

						<div class="card">
							<div class="result-list">
								{{range .Uploads}}
									<div class="result-item">
										<strong>{{.Name}}</strong>
										<a href="{{.URL}}">{{.URL}}</a>
									</div>
								{{end}}
							</div>
						</div>

						<div class="actions">
							<a class="btn btn-primary" href="{{(index .Uploads 0).URL}}">Открыть первый файл</a>
							<a class="btn btn-secondary" href="/">Загрузить еще</a>
							<a class="btn btn-secondary" href="/uploads">Все загруженные</a>
						</div>
					{{else if eq .Active "upload"}}
						<header class="page-header">
							<h1>Загрузить</h1>
						</header>

						{{if .Error}}<div class="alert alert-error" role="alert">{{.Error}}</div>{{end}}

						<div class="card">
							<form action="/upload" method="post" enctype="multipart/form-data" class="form">
								<div class="field">
									<label for="documents">Файлы</label>
									<input id="documents" name="documents" type="file" accept="application/pdf,.pdf,application/zip,.zip" multiple required>
									<p class="help">Можно выбрать несколько PDF или один ZIP-архив с PDF внутри. На каждый PDF будет создан отдельный URL.</p>
									<p class="limits">PDF до {{.MaxPDFMB}} МБ, вся загрузка до {{.MaxUploadMB}} МБ.</p>
								</div>

								<div class="form-actions">
									<button class="btn btn-primary" type="submit">Создать URL</button>
								</div>
							</form>
						</div>
					{{else if eq .Active "uploaded"}}
						<header class="page-header">
							<h1>Загруженные</h1>
						</header>

						{{if .Files}}
							<div class="table-list">
								{{range .Files}}
									<div class="file-row">
										<div class="file-main">
											<strong>{{.Name}}</strong>
											<div class="file-meta">
												<span>{{.Size}}</span>
												<span>{{.CreatedAt}}</span>
											</div>
											<a class="url" href="{{.URL}}">{{.URL}}</a>
										</div>
										<div class="file-actions">
											<a class="btn btn-secondary" href="{{.URL}}">Открыть</a>
											<a class="btn btn-primary" href="{{.Download}}">Скачать PDF</a>
										</div>
									</div>
								{{end}}
							</div>
						{{else}}
							<div class="empty-state">Пока нет загруженных PDF.</div>
						{{end}}
					{{else}}
						<header class="page-header">
							<h1>{{.Title}}</h1>
						</header>
						{{if .Error}}<div class="alert alert-error" role="alert">{{.Error}}</div>{{end}}
						<a class="btn btn-primary" href="/">Загрузить PDF</a>
					{{end}}
				</section>
			</div>
		{{end}}
	</main>
</body>
</html>`))

func main() {
	must(os.MkdirAll(filesDir, 0o775))
	must(os.MkdirAll(metaDir, 0o775))

	db, err := openAuthDB()
	must(err)
	defer db.Close()
	authDB = db

	if len(os.Args) > 1 {
		runCommand(db, os.Args[1:])
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", route)
	mux.HandleFunc("/assets/styles.css", styles)

	addr := listenAddr()
	log.Printf("listening on http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, securityHeaders(mux)))
}

func route(w http.ResponseWriter, r *http.Request) {
	switch {
	case isReadMethod(r.Method) && r.URL.Path == "/login":
		if isAuthenticated(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		renderLogin(w, "")
	case r.Method == http.MethodPost && r.URL.Path == "/login":
		login(w, r)
	case isReadMethod(r.Method) && r.URL.Path == "/logout":
		logout(w, r)
	case isReadMethod(r.Method) && r.URL.Path == "/":
		if !requireAuth(w, r) {
			return
		}
		renderUpload(w, "")
	case isReadMethod(r.Method) && r.URL.Path == "/uploads":
		if !requireAuth(w, r) {
			return
		}
		renderUploaded(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/upload":
		if !requireAuth(w, r) {
			return
		}
		upload(w, r)
	case isReadMethod(r.Method) && strings.HasPrefix(r.URL.Path, "/p/"):
		handlePDF(w, r)
	default:
		notFound(w)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderLogin(w, "Не удалось прочитать форму входа.")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	loginKey := loginLimitKey(r, username)

	if logins.blocked(loginKey) {
		renderLogin(w, "Слишком много попыток входа. Попробуйте позже.")
		return
	}

	if !validCredentials(username, password) {
		logins.recordFailure(loginKey)
		renderLogin(w, "Неверный логин или пароль.")
		return
	}
	logins.reset(loginKey)

	token, err := newSessionToken()
	if err != nil {
		http.Error(w, "cannot create session", http.StatusInternalServerError)
		return
	}
	sessions.set(token)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secureCookie(r),
		Expires:  time.Now().Add(24 * time.Hour),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		sessions.delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secureCookie(r),
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes+1024)
	if err := r.ParseMultipartForm(maxRequestBytes); err != nil {
		renderUpload(w, "Загрузка должна быть до 100 МБ.")
		return
	}

	headers := r.MultipartForm.File["documents"]
	headers = append(headers, r.MultipartForm.File["pdf"]...)
	if len(headers) == 0 {
		renderUpload(w, "Выберите PDF-файлы или ZIP-архив.")
		return
	}

	var uploads []uploadLink
	for _, header := range headers {
		name := sanitizeFileName(header.Filename)
		ext := strings.ToLower(filepath.Ext(name))

		file, err := header.Open()
		if err != nil {
			http.Error(w, "cannot read uploaded file", http.StatusInternalServerError)
			return
		}

		var metas []fileMeta
		switch ext {
		case ".pdf":
			if header.Size > maxPDFBytes {
				file.Close()
				renderUpload(w, "Каждый PDF должен быть до 25 МБ.")
				return
			}
			meta, err := savePDF(name, file)
			if err == nil {
				metas = append(metas, meta)
			}
		case ".zip":
			metas, err = saveZipPDFs(file)
		default:
			err = fmt.Errorf("unsupported file type")
		}
		file.Close()

		if err != nil {
			renderUpload(w, uploadErrorMessage(name, err))
			return
		}
		for _, meta := range metas {
			uploads = append(uploads, uploadLink{
				Name: meta.OriginalName,
				URL:  publicURL(r, meta),
			})
		}
	}

	if len(uploads) == 0 {
		renderUpload(w, "В загрузке не найдено PDF-файлов.")
		return
	}
	render(w, pageData{
		Title:   "Готово",
		Active:  "upload",
		Uploads: uploads,
	})
}

func saveZipPDFs(file io.Reader) ([]fileMeta, error) {
	data, err := io.ReadAll(io.LimitReader(file, maxRequestBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxRequestBytes {
		return nil, fmt.Errorf("request too large")
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("bad zip")
	}

	var metas []fileMeta
	var totalUncompressed uint64
	for _, zipped := range reader.File {
		if zipped.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(zipped.Name), ".pdf") {
			continue
		}
		if zipped.UncompressedSize64 > maxPDFBytes {
			return nil, fmt.Errorf("pdf too large")
		}
		totalUncompressed += zipped.UncompressedSize64
		if totalUncompressed > maxRequestBytes {
			return nil, fmt.Errorf("request too large")
		}

		rc, err := zipped.Open()
		if err != nil {
			return nil, err
		}
		meta, err := savePDF(sanitizeFileName(zipped.Name), rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		metas = append(metas, meta)
	}

	if len(metas) == 0 {
		return nil, fmt.Errorf("empty zip")
	}
	return metas, nil
}

func savePDF(name string, src io.Reader) (fileMeta, error) {
	var meta fileMeta
	limited := &io.LimitedReader{R: src, N: maxPDFBytes + 1}
	signature := make([]byte, 4)
	n, err := io.ReadFull(limited, signature)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return meta, err
	}
	if string(signature[:n]) != "%PDF" {
		return meta, fmt.Errorf("not pdf")
	}

	id, err := newSlug(name)
	if err != nil {
		return meta, err
	}

	targetName := id
	targetPath := filepath.Join(filesDir, targetName)
	out, err := os.Create(targetPath)
	if err != nil {
		return meta, err
	}
	defer out.Close()

	written, err := io.Copy(out, io.MultiReader(bytes.NewReader(signature[:n]), limited))
	if err != nil {
		_ = os.Remove(targetPath)
		return meta, err
	}
	if written > maxPDFBytes {
		_ = os.Remove(targetPath)
		return meta, fmt.Errorf("pdf too large")
	}

	meta = fileMeta{
		ID:           id,
		File:         targetName,
		OriginalName: name,
		Size:         written,
		CreatedAt:    time.Now().UTC(),
	}
	if err := saveMeta(meta); err != nil {
		_ = os.Remove(targetPath)
		return meta, err
	}
	return meta, nil
}

func uploadErrorMessage(name string, err error) string {
	switch err.Error() {
	case "unsupported file type":
		return "Можно загружать только PDF-файлы или ZIP-архивы."
	case "not pdf":
		return "Файл " + name + " не похож на настоящий PDF."
	case "pdf too large":
		return "Каждый PDF должен быть до 25 МБ."
	case "bad zip":
		return "Не удалось прочитать ZIP-архив."
	case "empty zip":
		return "В ZIP-архиве не найдено PDF-файлов."
	case "request too large":
		return "Загрузка должна быть до 100 МБ."
	default:
		return "Не удалось обработать файл " + name + "."
	}
}

func handlePDF(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "p" || parts[1] == "" {
		notFound(w)
		return
	}

	id, err := url.PathUnescape(parts[1])
	if err != nil || !validPublicID(id) {
		notFound(w)
		return
	}

	meta, err := loadMeta(id)
	if err != nil {
		notFound(w)
		return
	}

	if len(parts) == 2 {
		render(w, pageData{
			Title:    meta.OriginalName,
			FileName: meta.OriginalName,
			ID:       url.PathEscape(meta.ID),
			Wide:     true,
		})
		return
	}

	if parts[2] != "inline" && parts[2] != "download" {
		notFound(w)
		return
	}

	servePDF(w, r, meta, parts[2] == "download")
}

func servePDF(w http.ResponseWriter, r *http.Request, meta fileMeta, download bool) {
	path := filepath.Join(filesDir, filepath.Base(meta.File))
	f, err := os.Open(path)
	if err != nil {
		notFound(w)
		return
	}
	defer f.Close()

	disposition := "inline"
	if download {
		disposition = "attachment"
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": meta.OriginalName}))
	http.ServeContent(w, r, meta.OriginalName, meta.CreatedAt, f)
}

func renderUpload(w http.ResponseWriter, msg string) {
	render(w, pageData{
		Title:       "Загрузка PDF",
		Active:      "upload",
		Error:       msg,
		MaxUploadMB: maxRequestBytes >> 20,
		MaxPDFMB:    maxPDFBytes >> 20,
	})
}

func renderLogin(w http.ResponseWriter, msg string) {
	render(w, pageData{
		Title: "Вход",
		Error: msg,
		Login: true,
	})
}

func renderUploaded(w http.ResponseWriter, r *http.Request) {
	metas, err := loadAllMeta()
	if err != nil {
		http.Error(w, "cannot load files", http.StatusInternalServerError)
		return
	}

	files := make([]uploadedFile, 0, len(metas))
	for _, meta := range metas {
		url := publicURL(r, meta)
		files = append(files, uploadedFile{
			Name:      meta.OriginalName,
			URL:       url,
			Download:  url + "/download",
			Size:      formatBytes(meta.Size),
			CreatedAt: meta.CreatedAt.Local().Format("2006-01-02 15:04"),
		})
	}

	render(w, pageData{
		Title:  "Загруженные",
		Active: "uploaded",
		Files:  files,
	})
}

func render(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, data); err != nil {
		log.Printf("render error: %v", err)
	}
}

func notFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	render(w, pageData{Title: "Файл не найден", Error: "PDF по этой ссылке не найден."})
}

func saveMeta(meta fileMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(metaDir, meta.ID+".json"), data, 0o664)
}

func loadMeta(id string) (fileMeta, error) {
	if !validPublicID(id) {
		return fileMeta{}, fmt.Errorf("invalid public id")
	}

	var meta fileMeta
	data, err := os.ReadFile(filepath.Join(metaDir, id+".json"))
	if err != nil {
		return meta, err
	}
	return meta, json.Unmarshal(data, &meta)
}

func loadAllMeta() ([]fileMeta, error) {
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		return nil, err
	}

	metas := make([]fileMeta, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		meta, err := loadMeta(id)
		if err != nil {
			continue
		}
		metas = append(metas, meta)
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].CreatedAt.After(metas[j].CreatedAt)
	})
	return metas, nil
}

func newSlug(name string) (string, error) {
	base := slugFileName(name)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	for i := 0; i < 1000; i++ {
		id := base
		if i > 0 {
			id = fmt.Sprintf("%s-%d%s", stem, i+1, ext)
		}
		if _, err := os.Stat(filepath.Join(metaDir, id+".json")); errors.Is(err, os.ErrNotExist) {
			return id, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("cannot allocate public URL for file")
}

func slugFileName(name string) string {
	name = sanitizeFileName(name)
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".pdf" {
		name = strings.TrimSuffix(name, filepath.Ext(name)) + ".pdf"
	}
	if name == ".pdf" {
		return "document.pdf"
	}
	return name
}

func sanitizeFileName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r >= 128:
			return r
		case r == '.', r == '-', r == '_', r == ' ':
			return r
		default:
			return '_'
		}
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "document.pdf"
	}
	return name
}

func validPublicID(id string) bool {
	return id == filepath.Base(id) && id != "." && id != ".." && strings.TrimSpace(id) != ""
}

func publicURL(r *http.Request, meta fileMeta) string {
	return baseURL(r) + "/p/" + url.PathEscape(meta.ID)
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func styles(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write([]byte(css))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func isReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if isAuthenticated(r) {
		return true
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	return false
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return sessions.valid(cookie.Value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; frame-src 'self'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(w, r)
	})
}

func loginLimitKey(r *http.Request, username string) string {
	return clientIP(r) + "|" + strings.ToLower(strings.TrimSpace(username))
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func secureCookie(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func openAuthDB() (*sql.DB, error) {
	db, err := sql.Open("postgres", envOrDefault("DATABASE_URL", defaultDBURL))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)

	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func runMigrations(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return err
	}

	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return err
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		applied, err := migrationApplied(db, name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		if err := applyMigration(db, name); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}

	return nil
}

func migrationApplied(db *sql.DB, name string) (bool, error) {
	var exists bool
	err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, name).Scan(&exists)
	return exists, err
}

func applyMigration(db *sql.DB, name string) error {
	sqlBytes, err := migrationFiles.ReadFile(filepath.Join("migrations", name))
	if err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(string(sqlBytes)); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
		return err
	}

	return tx.Commit()
}

func runCommand(db *sql.DB, args []string) {
	switch args[0] {
	case "create-user":
		if len(args) != 3 {
			log.Fatal("usage: go run . create-user <login> <password>")
		}
		if err := createInitialUser(db, args[1], args[2]); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("created user %q\n", args[1])
	default:
		log.Fatalf("unknown command %q\nusage: go run . create-user <login> <password>", args[0])
	}
}

func createInitialUser(db *sql.DB, username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("login cannot be empty")
	}
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("users table is not empty; refusing to create another initial user")
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.Exec(
		`INSERT INTO users (username, password_hash, created_at, updated_at) VALUES ($1, $2, $3, $4)`,
		username,
		passwordHash,
		now,
		now,
	)
	return err
}

func validCredentials(username, password string) bool {
	if authDB == nil {
		return false
	}

	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return false
	}

	var passwordHash string
	err := authDB.QueryRow(`SELECT password_hash FROM users WHERE username = $1`, username).Scan(&passwordHash)
	if err != nil {
		return false
	}

	ok, err := verifyPassword(password, passwordHash)
	return err == nil && ok
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := pbkdf2Key([]byte(password), salt, passwordIters, sha256.Size)
	return fmt.Sprintf(
		"pbkdf2_sha256$%d$%s$%s",
		passwordIters,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func verifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false, fmt.Errorf("unsupported password hash")
	}

	var iterations int
	if _, err := fmt.Sscanf(parts[1], "%d", &iterations); err != nil {
		return false, err
	}
	if iterations <= 0 {
		return false, fmt.Errorf("invalid password iterations")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, err
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, err
	}

	actual := pbkdf2Key([]byte(password), salt, iterations, len(expected))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func pbkdf2Key(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var key []byte

	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)

		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		key = append(key, t...)
	}
	return key[:keyLen]
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func newSessionToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (s *sessionStore) set(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[token] = time.Now().Add(24 * time.Hour)
}

func (s *sessionStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiresAt, ok := s.values[token]
	if !ok {
		return false
	}
	if time.Now().After(expiresAt) {
		delete(s.values, token)
		return false
	}
	return true
}

func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, token)
}

func newLoginLimiter(limit int, window time.Duration) *loginLimiter {
	return &loginLimiter{
		limit:    limit,
		window:   window,
		attempts: map[string]loginAttempt{},
	}
}

func (l *loginLimiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	attempt, ok := l.attempts[key]
	if !ok {
		return false
	}
	if time.Now().After(attempt.expiresAt) {
		delete(l.attempts, key)
		return false
	}
	return attempt.count >= l.limit
}

func (l *loginLimiter) recordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	attempt, ok := l.attempts[key]
	if !ok || now.After(attempt.expiresAt) {
		l.attempts[key] = loginAttempt{count: 1, expiresAt: now.Add(l.window)}
		return
	}
	attempt.count++
	l.attempts[key] = attempt
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

func listenAddr() string {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		return defaultAddr
	}
	if strings.HasPrefix(port, ":") {
		return port
	}
	return ":" + port
}

func formatBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

const css = `:root {
    color-scheme: light;
    --bg: #f4f6f8;
    --surface: #ffffff;
    --surface-muted: #f8fafc;
    --border: #d8dee8;
    --border-strong: #c6ceda;
    --text: #1f2937;
    --muted: #64748b;
    --primary: #1d4ed8;
    --primary-hover: #1e40af;
    --secondary: #eef2f7;
    --secondary-hover: #e2e8f0;
    --danger-bg: #fef2f2;
    --danger-border: #fecaca;
    --danger-text: #991b1b;
    --success-bg: #f0fdf4;
    --success-border: #bbf7d0;
    --success-text: #166534;
    font-family: Arial, Helvetica, sans-serif;
    background: var(--bg);
    color: var(--text);
}

* {
    box-sizing: border-box;
}

html {
    min-width: 320px;
}

body {
    min-height: 100vh;
    margin: 0;
    background: var(--bg);
}

a {
    color: var(--primary);
    text-decoration-thickness: 1px;
    text-underline-offset: 2px;
}

.page {
    min-height: 100vh;
}

.app-layout {
    display: grid;
    grid-template-columns: 240px minmax(0, 1fr);
    min-height: 100vh;
}

.sidebar {
    border-right: 1px solid var(--border);
    background: var(--surface);
    padding: 20px 14px;
}

.brand {
    padding: 0 10px 18px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 14px;
}

.brand strong {
    display: block;
    color: #111827;
    font-size: 16px;
    line-height: 1.35;
}

.sidebar-nav {
    display: grid;
    gap: 4px;
}

.sidebar-nav a {
    display: flex;
    align-items: center;
    min-height: 40px;
    border-radius: 6px;
    padding: 9px 10px;
    color: #334155;
    font-size: 14px;
    font-weight: 700;
    text-decoration: none;
}

.sidebar-nav a:hover,
.sidebar-nav a.active {
    background: #e8f0fe;
    color: var(--primary);
}

.workspace {
    min-width: 0;
    padding: 28px;
}

.page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 18px;
}

.page-header h1 {
    margin: 0;
    color: #111827;
    font-size: 26px;
    line-height: 1.2;
}

.card {
    max-width: 920px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    padding: 20px;
}

.login-screen {
    display: grid;
    min-height: 100vh;
    place-items: center;
    padding: 24px;
}

.login-panel {
    width: min(100%, 400px);
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    padding: 28px;
    box-shadow: 0 14px 40px rgba(15, 23, 42, 0.08);
}

.login-heading {
    margin-bottom: 22px;
}

.login-heading h1 {
    margin: 0;
    color: #111827;
    font-size: 24px;
    line-height: 1.2;
}

.login-heading p {
    margin: 8px 0 0;
    color: var(--muted);
    font-size: 14px;
}

.form {
    display: grid;
    gap: 18px;
}

.form-login {
    gap: 16px;
}

.field {
    display: grid;
    min-width: 0;
    gap: 8px;
}

.field label {
    color: #475569;
    font-size: 13px;
    font-weight: 700;
}

input[type="text"],
input[type="password"],
input[type="file"] {
    width: 100%;
    min-width: 0;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    background: #ffffff;
    color: var(--text);
    font: inherit;
    padding: 11px 12px;
}

input[type="file"] {
    min-height: 46px;
    color: #334155;
}

input:focus {
    border-color: var(--primary);
    outline: 3px solid rgba(29, 78, 216, 0.14);
}

.help,
.limits {
    margin: 0;
    color: var(--muted);
    font-size: 14px;
    line-height: 1.5;
}

.limits {
    font-size: 13px;
}

.form-actions,
.actions {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}

.actions {
    margin-top: 18px;
}

.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    max-width: 100%;
    min-height: 40px;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 9px 14px;
    font: inherit;
    font-size: 14px;
    font-weight: 700;
    line-height: 1.2;
    text-align: center;
    text-decoration: none;
    cursor: pointer;
    white-space: normal;
}

.btn-primary {
    background: var(--primary);
    color: #ffffff;
}

.btn-primary:hover {
    background: var(--primary-hover);
}

.btn-secondary {
    border-color: var(--border);
    background: var(--secondary);
    color: var(--text);
}

.btn-secondary:hover {
    background: var(--secondary-hover);
}

.alert {
    max-width: 920px;
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 16px;
    font-size: 14px;
    line-height: 1.45;
}

.alert-error {
    border: 1px solid var(--danger-border);
    background: var(--danger-bg);
    color: var(--danger-text);
}

.alert-success {
    border: 1px solid var(--success-border);
    background: var(--success-bg);
    color: var(--success-text);
}

.result-list {
    display: grid;
    gap: 14px;
}

.result-item {
    display: grid;
    gap: 5px;
    min-width: 0;
    border-bottom: 1px solid var(--border);
    padding-bottom: 14px;
}

.result-item:last-child {
    border-bottom: 0;
    padding-bottom: 0;
}

.result-item strong,
.result-item a,
.url {
    overflow-wrap: anywhere;
    word-break: break-word;
}

.table-list {
    display: grid;
    gap: 10px;
}

.file-row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    gap: 16px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    padding: 14px;
}

.file-main {
    display: grid;
    min-width: 0;
    gap: 6px;
}

.file-main strong {
    color: #111827;
    line-height: 1.35;
    overflow-wrap: anywhere;
}

.file-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 12px;
    color: var(--muted);
    font-size: 13px;
}

.file-actions {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 8px;
}

.empty-state {
    max-width: 920px;
    border: 1px dashed var(--border-strong);
    border-radius: 8px;
    background: var(--surface);
    color: var(--muted);
    padding: 30px 18px;
    text-align: center;
}

.public-pdf {
    min-height: 100vh;
    background: var(--bg);
    padding: 14px;
}

.public-pdf-actions {
    width: min(1120px, 100%);
    margin: 0 auto 12px;
    display: flex;
    justify-content: flex-end;
}

.pdf-viewer {
    width: min(1120px, 100%);
    margin: 0 auto;
    overflow: hidden;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    box-shadow: 0 14px 36px rgba(15, 23, 42, 0.10);
}

.pdf-viewer iframe {
    display: block;
    width: 100%;
    height: calc(100vh - 82px);
    min-height: 620px;
    border: 0;
    background: var(--surface);
}

@media (max-width: 760px) {
    .app-layout {
        grid-template-columns: 1fr;
    }

    .sidebar {
        border-right: 0;
        border-bottom: 1px solid var(--border);
        padding: 14px;
    }

    .brand {
        padding: 0 4px 12px;
        margin-bottom: 10px;
    }

    .sidebar-nav {
        grid-template-columns: repeat(3, minmax(0, 1fr));
    }

    .sidebar-nav a {
        justify-content: center;
        min-height: 38px;
        padding: 8px;
        text-align: center;
    }

    .workspace {
        padding: 18px;
    }

    .page-header {
        margin-bottom: 14px;
    }

    .page-header h1 {
        font-size: 22px;
    }

    .card,
    .login-panel {
        padding: 18px;
    }

    .file-row {
        grid-template-columns: 1fr;
        align-items: stretch;
    }

    .file-actions,
    .actions,
    .form-actions {
        flex-direction: column;
        align-items: stretch;
    }

    .btn {
        width: 100%;
    }

    .public-pdf {
        padding: 8px;
    }

    .public-pdf-actions {
        margin-bottom: 8px;
    }

    .pdf-viewer {
        border-radius: 6px;
    }

    .pdf-viewer iframe {
        height: calc(100vh - 64px);
        min-height: 520px;
    }
}`
