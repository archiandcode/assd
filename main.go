package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
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
	defaultAddr       = ":8010"
	defaultDBURL      = "host=/tmp/url-generator-postgres port=5432 user=url_generator password=url_generator_password dbname=url_generator sslmode=disable"
	sessionCookie     = "url_generator_session"
	passwordIters     = 210000
	publicIDLength    = 5
	maxWebSocketBytes = 100 << 20
)

var (
	filesDir = filepath.Join("storage", "files")
	metaDir  = filepath.Join("storage", "meta")
	sessions = sessionStore{values: map[string]time.Time{}}
	authDB   *sql.DB
	logins   = newLoginLimiter(5, 10*time.Minute)
	idMu     sync.Mutex
	csrfKey  = mustRandomKey()
)

type fileMeta struct {
	ID           string    `json:"id"`
	File         string    `json:"file"`
	OriginalName string    `json:"original_name"`
	LinkPath     string    `json:"link_path"`
	Size         int64     `json:"size"`
	CreatedAt    time.Time `json:"created_at"`
}

type pageData struct {
	Title     string
	Active    string
	Error     string
	Query     string
	Login     bool
	NotFound  bool
	Uploads   []uploadLink
	Files     []uploadedFile
	FileName  string
	ID        string
	Wide      bool
	CSRFToken string
}

type zipReader interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}

type uploadLink struct {
	Name string
	URL  string
	ID   string
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
	{{if .CSRFToken}}<meta name="csrf-token" content="{{.CSRFToken}}">{{end}}
	<link rel="stylesheet" href="/assets/styles.css">
</head>
<body>
	<main class="page{{if .Wide}} page-public{{end}}">
		{{if .NotFound}}
			<section class="not-found-screen">
				<div class="not-found-panel">
					<p>404</p>
					<h1>Страница не существует</h1>
				</div>
			</section>
		{{else if .Login}}
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
					<a class="btn btn-primary" href="/{{.ID}}/download">Скачать PDF</a>
				</div>
				<div class="pdf-viewer" data-pdf-viewer data-pdf-url="/{{.ID}}/inline">
					<div class="pdf-status" data-pdf-status>Загрузка PDF...</div>
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
						<a class="{{if eq .Active "delete"}}active{{end}}" href="/delete">Удалить</a>
					</nav>
				</aside>

				<div class="app-main">
					<header class="topbar">
						<div></div>
						<a class="btn btn-secondary" href="/logout">Выйти</a>
					</header>

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
							<form action="/upload?csrf_token={{.CSRFToken}}" method="post" enctype="multipart/form-data" class="form" data-upload-form>
								<div class="field">
									<label for="documents">Файлы</label>
									<input id="documents" name="documents" type="file" accept="application/pdf,.pdf,application/zip,.zip" multiple required>
									<p class="help">Можно выбрать несколько PDF или один ZIP-архив с PDF внутри. На каждый PDF будет создан отдельный URL.</p>
								</div>

								<div class="form-actions">
									<button class="btn btn-primary" type="submit">Создать URL</button>
								</div>
							</form>
						</div>

						<div class="progress-panel" data-progress hidden>
							<div class="progress-top">
								<strong data-progress-title>Обработка</strong>
								<span data-progress-percent>0%</span>
							</div>
							<div class="progress-track">
								<div class="progress-bar" data-progress-bar></div>
							</div>
							<p data-progress-message></p>
						</div>
					{{else if eq .Active "uploaded"}}
						<header class="page-header">
							<h1>Загруженные</h1>
							<button class="btn btn-primary" type="button" data-export-xlsx>Выгрузить XLSX</button>
						</header>

						<form action="/uploads" method="get" class="search-form">
							<input name="q" type="text" value="{{.Query}}" placeholder="Поиск по названию или коду ссылки">
							<button class="btn btn-secondary" type="submit">Найти</button>
							{{if .Query}}<a class="btn btn-secondary" href="/uploads">Сбросить</a>{{end}}
						</form>

						<div class="progress-panel" data-progress hidden>
							<div class="progress-top">
								<strong data-progress-title>Обработка</strong>
								<span data-progress-percent>0%</span>
							</div>
							<div class="progress-track">
								<div class="progress-bar" data-progress-bar></div>
							</div>
							<p data-progress-message></p>
						</div>

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
					{{else if eq .Active "delete"}}
						<header class="page-header">
							<h1>Удалить</h1>
						</header>

						<div class="card tools-card">
							<form class="form" data-delete-form>
								<div class="field">
									<label for="delete-xlsx">XLSX со ссылками</label>
									<input id="delete-xlsx" name="delete-xlsx" type="file" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" required>
									<p class="help">В XLSX должна быть колонка "Ссылка" или "Код". Если заголовков нет, укажите ссылки или коды в первой колонке.</p>
								</div>
								<div class="form-actions">
									<button class="btn btn-primary" type="submit">Удалить найденные</button>
								</div>
							</form>
						</div>

						<div class="progress-panel" data-progress hidden>
							<div class="progress-top">
								<strong data-progress-title>Обработка</strong>
								<span data-progress-percent>0%</span>
							</div>
							<div class="progress-track">
								<div class="progress-bar" data-progress-bar></div>
							</div>
							<p data-progress-message></p>
						</div>
					{{else}}
						<header class="page-header">
							<h1>{{.Title}}</h1>
						</header>
						{{if .Error}}<div class="alert alert-error" role="alert">{{.Error}}</div>{{end}}
						<a class="btn btn-primary" href="/">Загрузить PDF</a>
					{{end}}
					</section>
				</div>
			</div>
		{{end}}
	</main>
	{{if .ID}}<script src="https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js"></script>{{end}}
	<script src="/assets/export.js"></script>
</body>
</html>`))

func main() {
	must(os.MkdirAll(filesDir, 0o775))
	must(os.MkdirAll(metaDir, 0o775))

	db, err := openAuthDB()
	must(err)
	defer db.Close()
	authDB = db
	must(migrateLegacyMeta(db))
	must(normalizeStoredLinkPaths(db))

	if len(os.Args) > 1 {
		runCommand(db, os.Args[1:])
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", route)
	mux.HandleFunc("/assets/styles.css", styles)
	mux.HandleFunc("/assets/export.js", exportScript)

	addr := listenAddr()
	log.Printf("listening on http://localhost%s", addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
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
		renderUpload(w, r, "")
	case isReadMethod(r.Method) && r.URL.Path == "/uploads":
		if !requireAuth(w, r) {
			return
		}
		renderUploaded(w, r)
	case isReadMethod(r.Method) && r.URL.Path == "/delete":
		if !requireAuth(w, r) {
			return
		}
		renderDelete(w, r)
	case isReadMethod(r.Method) && r.URL.Path == "/ws/uploads.xlsx":
		if !requireAuth(w, r) {
			return
		}
		if !requireCSRF(w, r) {
			return
		}
		exportUploadsXLSX(w, r)
	case isReadMethod(r.Method) && r.URL.Path == "/ws/delete.xlsx":
		if !requireAuth(w, r) {
			return
		}
		if !requireCSRF(w, r) {
			return
		}
		deleteUploadsXLSX(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/upload":
		if !requireAuth(w, r) {
			return
		}
		if !requireCSRF(w, r) {
			return
		}
		upload(w, r)
	case isReadMethod(r.Method) && isPDFPath(r.URL.Path):
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
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		renderUpload(w, r, "Не удалось прочитать загрузку.")
		return
	}

	headers := r.MultipartForm.File["documents"]
	headers = append(headers, r.MultipartForm.File["pdf"]...)
	if len(headers) == 0 {
		renderUpload(w, r, "Выберите PDF-файлы или ZIP-архив.")
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
			renderUpload(w, r, uploadErrorMessage(name, err))
			return
		}
		for _, meta := range metas {
			uploads = append(uploads, uploadLink{
				Name: meta.OriginalName,
				URL:  publicURL(r, meta),
				ID:   meta.ID,
			})
		}
	}

	if len(uploads) == 0 {
		renderUpload(w, r, "В загрузке не найдено PDF-файлов.")
		return
	}
	render(w, pageData{
		Title:     "Готово",
		Active:    "upload",
		Uploads:   uploads,
		CSRFToken: csrfToken(r),
	})
}

func saveZipPDFs(file zipReader) ([]fileMeta, error) {
	size, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	reader, err := zip.NewReader(file, size)
	if err != nil {
		return nil, fmt.Errorf("bad zip")
	}

	var metas []fileMeta
	for _, zipped := range zipPDFEntries(reader.File) {
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

func zipPDFEntries(files []*zip.File) []*zip.File {
	pdfs := make([]*zip.File, 0, len(files))
	for _, file := range files {
		if file.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(file.Name), ".pdf") {
			continue
		}
		pdfs = append(pdfs, file)
	}
	return pdfs
}

func savePDF(name string, src io.Reader) (fileMeta, error) {
	var meta fileMeta
	signature := make([]byte, 4)
	n, err := io.ReadFull(src, signature)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return meta, err
	}
	if string(signature[:n]) != "%PDF" {
		return meta, fmt.Errorf("not pdf")
	}

	idMu.Lock()
	defer idMu.Unlock()

	id, err := newPublicID()
	if err != nil {
		return meta, err
	}

	targetName := filepath.Join(id, name)
	targetPath := filepath.Join(filesDir, targetName)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o775); err != nil {
		return meta, err
	}
	out, err := os.Create(targetPath)
	if err != nil {
		return meta, err
	}
	defer out.Close()

	written, err := io.Copy(out, io.MultiReader(bytes.NewReader(signature[:n]), src))
	if err != nil {
		_ = os.Remove(targetPath)
		return meta, err
	}

	meta = fileMeta{
		ID:           id,
		File:         targetName,
		OriginalName: name,
		LinkPath:     "/" + id,
		Size:         written,
		CreatedAt:    time.Now().UTC(),
	}
	if err := saveMeta(meta); err != nil {
		_ = os.Remove(targetPath)
		_ = os.Remove(filepath.Dir(targetPath))
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
	case "bad zip":
		return "Не удалось прочитать ZIP-архив."
	case "empty zip":
		return "В ZIP-архиве не найдено PDF-файлов."
	default:
		return "Не удалось обработать файл " + name + "."
	}
}

func handlePDF(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 1 || len(parts) > 3 || parts[0] == "" {
		notFound(w)
		return
	}

	if parts[0] == "p" {
		if len(parts) < 2 || parts[1] == "" {
			notFound(w)
			return
		}
		redirectLegacyPDFPath(w, r, parts)
		return
	}

	if len(parts) > 2 {
		notFound(w)
		return
	}

	id, err := url.PathUnescape(parts[0])
	if err != nil || !validPublicID(id) {
		notFound(w)
		return
	}

	meta, err := loadMeta(id)
	if err != nil {
		notFound(w)
		return
	}

	if len(parts) == 1 {
		render(w, pageData{
			Title:    meta.OriginalName,
			FileName: meta.OriginalName,
			ID:       url.PathEscape(meta.ID),
			Wide:     true,
		})
		return
	}

	if parts[1] != "inline" && parts[1] != "download" {
		notFound(w)
		return
	}

	servePDF(w, r, meta, parts[1] == "download")
}

func isPDFPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return false
	}
	if parts[0] == "p" {
		return len(parts) == 2 || len(parts) == 3
	}
	if isReservedPath(parts[0]) {
		return false
	}
	return len(parts) == 1 || len(parts) == 2
}

func isReservedPath(first string) bool {
	switch first {
	case "assets", "delete", "login", "logout", "upload", "uploads", "ws":
		return true
	default:
		return false
	}
}

func redirectLegacyPDFPath(w http.ResponseWriter, r *http.Request, parts []string) {
	id, err := url.PathUnescape(parts[1])
	if err != nil || !validPublicID(id) {
		notFound(w)
		return
	}

	target := "/" + url.PathEscape(id)
	if len(parts) == 3 {
		if parts[2] != "inline" && parts[2] != "download" {
			notFound(w)
			return
		}
		target += "/" + parts[2]
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func servePDF(w http.ResponseWriter, r *http.Request, meta fileMeta, download bool) {
	path, err := storedFilePath(meta.File)
	if err != nil {
		notFound(w)
		return
	}
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

func renderUpload(w http.ResponseWriter, r *http.Request, msg string) {
	render(w, pageData{
		Title:     "Загрузка PDF",
		Active:    "upload",
		Error:     msg,
		CSRFToken: csrfToken(r),
	})
}

func renderLogin(w http.ResponseWriter, msg string) {
	render(w, pageData{
		Title: "Вход",
		Error: msg,
		Login: true,
	})
}

func renderDelete(w http.ResponseWriter, r *http.Request) {
	render(w, pageData{
		Title:     "Удалить",
		Active:    "delete",
		CSRFToken: csrfToken(r),
	})
}

func renderUploaded(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	var metas []fileMeta
	var err error
	if query != "" {
		metas, err = searchMeta(query)
		if err != nil {
			http.Error(w, "cannot search files", http.StatusInternalServerError)
			return
		}
	} else {
		metas, err = loadAllMeta()
		if err != nil {
			http.Error(w, "cannot load files", http.StatusInternalServerError)
			return
		}
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
		Title:     "Загруженные",
		Active:    "uploaded",
		Query:     query,
		Files:     files,
		CSRFToken: csrfToken(r),
	})
}

func exportUploadsXLSX(w http.ResponseWriter, r *http.Request) {
	conn, err := acceptWebSocket(w, r)
	if err != nil {
		return
	}
	defer conn.close()

	_ = conn.writeProgress("export", 5, "Загружаем список файлов...")
	metas, err := loadAllMeta()
	if err != nil {
		_ = conn.writeClose("cannot load files")
		return
	}
	_ = conn.writeProgress("export", 35, "Сортируем данные...")
	sortUploadsForExport(metas)

	_ = conn.writeProgress("export", 65, "Формируем XLSX...")
	xlsx, err := buildUploadsXLSX(metas)
	if err != nil {
		_ = conn.writeClose("cannot build xlsx")
		return
	}
	_ = conn.writeProgress("export", 90, "Отправляем файл...")
	if err := conn.writeBinary(xlsx); err != nil {
		return
	}
	_ = conn.writeProgress("export", 100, "Готово.")
	_ = conn.writeClose("")
}

func sortUploadsForExport(metas []fileMeta) {
	sort.Slice(metas, func(i, j int) bool {
		return metas[i].CreatedAt.After(metas[j].CreatedAt)
	})
}

func deleteUploadsXLSX(w http.ResponseWriter, r *http.Request) {
	conn, err := acceptWebSocket(w, r)
	if err != nil {
		return
	}
	defer conn.close()

	_ = conn.writeProgress("delete", 5, "Ждем XLSX-файл...")
	data, err := conn.readBinary(maxWebSocketBytes)
	if err != nil {
		_ = conn.writeClose("cannot read xlsx")
		return
	}

	_ = conn.writeProgress("delete", 20, "Читаем ссылки из XLSX...")
	ids, err := readXLSXDeleteIDs(data)
	if err != nil {
		_ = conn.writeClose("cannot parse xlsx")
		return
	}
	if len(ids) == 0 {
		_ = conn.writeClose("xlsx has no links")
		return
	}

	_ = conn.writeProgress("delete", 40, "Ищем совпадения...")
	metas, err := loadAllMeta()
	if err != nil {
		_ = conn.writeClose("cannot load files")
		return
	}

	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}

	deleted := 0
	total := len(metas)
	for i, meta := range metas {
		if wanted[meta.ID] {
			if err := deleteMeta(meta); err != nil {
				_ = conn.writeClose("cannot delete files")
				return
			}
			deleted++
		}
		progress := 40
		if total > 0 {
			progress = 40 + int(float64(i+1)/float64(total)*55)
		}
		_ = conn.writeProgress("delete", progress, fmt.Sprintf("Удалено: %d", deleted))
	}

	_ = conn.writeProgress("delete", 100, fmt.Sprintf("Готово. Удалено файлов: %d", deleted))
	_ = conn.writeClose("")
}

func render(w http.ResponseWriter, data pageData) {
	renderStatus(w, http.StatusOK, data)
}

func renderStatus(w http.ResponseWriter, status int, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := page.Execute(w, data); err != nil {
		log.Printf("render error: %v", err)
	}
}

func notFound(w http.ResponseWriter) {
	renderStatus(w, http.StatusNotFound, pageData{Title: "Страница не существует", NotFound: true})
}

func saveMeta(meta fileMeta) error {
	if authDB == nil {
		return fmt.Errorf("database is not ready")
	}
	meta.LinkPath = normalizeLinkPath(meta.ID, meta.LinkPath)
	_, err := authDB.Exec(
		`INSERT INTO pdf_files (id, file_path, original_name, link_path, size, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (id) DO UPDATE SET
			file_path = EXCLUDED.file_path,
			original_name = EXCLUDED.original_name,
			link_path = EXCLUDED.link_path,
			size = EXCLUDED.size,
			created_at = EXCLUDED.created_at`,
		meta.ID,
		meta.File,
		meta.OriginalName,
		meta.LinkPath,
		meta.Size,
		meta.CreatedAt,
	)
	return err
}

func loadMeta(id string) (fileMeta, error) {
	if !validPublicID(id) {
		return fileMeta{}, fmt.Errorf("invalid public id")
	}

	var meta fileMeta
	err := authDB.QueryRow(
		`SELECT id, file_path, original_name, link_path, size, created_at FROM pdf_files WHERE id = $1`,
		id,
	).Scan(&meta.ID, &meta.File, &meta.OriginalName, &meta.LinkPath, &meta.Size, &meta.CreatedAt)
	return meta, err
}

func loadAllMeta() ([]fileMeta, error) {
	rows, err := authDB.Query(
		`SELECT id, file_path, original_name, link_path, size, created_at
		 FROM pdf_files
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metas []fileMeta
	for rows.Next() {
		var meta fileMeta
		if err := rows.Scan(&meta.ID, &meta.File, &meta.OriginalName, &meta.LinkPath, &meta.Size, &meta.CreatedAt); err != nil {
			return nil, err
		}
		metas = append(metas, meta)
	}
	return metas, rows.Err()
}

func searchMeta(query string) ([]fileMeta, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return loadAllMeta()
	}
	like := "%" + strings.ToLower(query) + "%"
	rows, err := authDB.Query(
		`SELECT id, file_path, original_name, link_path, size, created_at
		 FROM pdf_files
		 WHERE LOWER(original_name) LIKE $1
		    OR LOWER(id) LIKE $1
		    OR LOWER(link_path) LIKE $1
		 ORDER BY created_at DESC`,
		like,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metas []fileMeta
	for rows.Next() {
		var meta fileMeta
		if err := rows.Scan(&meta.ID, &meta.File, &meta.OriginalName, &meta.LinkPath, &meta.Size, &meta.CreatedAt); err != nil {
			return nil, err
		}
		metas = append(metas, meta)
	}
	return metas, rows.Err()
}

func deleteMeta(meta fileMeta) error {
	filePath, err := storedFilePath(meta.File)
	if err != nil {
		return err
	}
	if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(filepath.Dir(filePath))
	_, err = authDB.Exec(`DELETE FROM pdf_files WHERE id = $1`, meta.ID)
	return err
}

func storedFilePath(name string) (string, error) {
	clean := filepath.Clean(name)
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", fmt.Errorf("invalid stored file path")
	}
	return filepath.Join(filesDir, clean), nil
}

func newPublicID() (string, error) {
	for i := 0; i < 1000; i++ {
		id, err := randomPublicID()
		if err != nil {
			return "", err
		}
		var exists bool
		if err := authDB.QueryRow(`SELECT EXISTS (SELECT 1 FROM pdf_files WHERE id = $1)`, id).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return id, nil
		}
	}
	return "", fmt.Errorf("cannot allocate public URL for file")
}

func randomPublicID() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b [publicIDLength]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := make([]byte, publicIDLength)
	for i, n := range b {
		id[i] = alphabet[int(n)%len(alphabet)]
	}
	return string(id), nil
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
	return baseURL(r) + normalizeLinkPath(meta.ID, meta.LinkPath)
}

func normalizeLinkPath(id, linkPath string) string {
	id = url.PathEscape(id)
	linkPath = strings.TrimSpace(linkPath)
	if linkPath == "" {
		return "/" + id
	}
	if strings.HasPrefix(linkPath, "/p/") {
		return "/" + strings.TrimPrefix(linkPath, "/p/")
	}
	if !strings.HasPrefix(linkPath, "/") {
		return "/" + linkPath
	}
	return linkPath
}

func baseURL(r *http.Request) string {
	if configured := configuredBaseURL(); configured != "" {
		return configured
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func configuredBaseURL() string {
	baseURL := strings.TrimSpace(os.Getenv("APP_BASE_URL"))
	if baseURL == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(baseURL), "http://") && !strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		baseURL = "https://" + baseURL
	}
	return strings.TrimRight(baseURL, "/")
}

func styles(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write([]byte(css))
}

func exportScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write([]byte(js))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func mustRandomKey() [32]byte {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		log.Fatalf("generate csrf key: %v", err)
	}
	return key
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

func requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	if validCSRF(r) {
		return true
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return false
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return sessions.valid(cookie.Value)
}

func csrfToken(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || !sessions.valid(cookie.Value) {
		return ""
	}
	return csrfTokenForSession(cookie.Value)
}

func validCSRF(r *http.Request) bool {
	got := strings.TrimSpace(r.URL.Query().Get("csrf_token"))
	if got == "" {
		got = strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	}
	want := csrfToken(r)
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func csrfTokenForSession(sessionToken string) string {
	mac := hmac.New(sha256.New, csrfKey[:])
	mac.Write([]byte(sessionToken))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; connect-src 'self' ws: wss:; worker-src 'self' blob: https://cdn.jsdelivr.net; base-uri 'self'; object-src 'none'; frame-src 'self'; form-action 'self'")
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

func migrateLegacyMeta(db *sql.DB) error {
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(metaDir, entry.Name()))
		if err != nil {
			return err
		}
		var meta fileMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			return err
		}
		if meta.ID == "" || meta.OriginalName == "" {
			continue
		}
		meta.LinkPath = normalizeLinkPath(meta.ID, meta.LinkPath)
		if meta.File == "" {
			meta.File = meta.ID
		}
		meta.File = migrateLegacyPDFPath(meta)

		_, err = db.Exec(
			`INSERT INTO pdf_files (id, file_path, original_name, link_path, size, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (id) DO NOTHING`,
			meta.ID,
			meta.File,
			meta.OriginalName,
			meta.LinkPath,
			meta.Size,
			meta.CreatedAt,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func normalizeStoredLinkPaths(db *sql.DB) error {
	rows, err := db.Query(`SELECT id, link_path FROM pdf_files`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type update struct {
		id   string
		link string
	}
	var updates []update
	for rows.Next() {
		var id, linkPath string
		if err := rows.Scan(&id, &linkPath); err != nil {
			return err
		}
		normalized := normalizeLinkPath(id, linkPath)
		if normalized != linkPath {
			updates = append(updates, update{id: id, link: normalized})
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, item := range updates {
		if _, err := db.Exec(`UPDATE pdf_files SET link_path = $1 WHERE id = $2`, item.link, item.id); err != nil {
			return err
		}
	}
	return nil
}

func migrateLegacyPDFPath(meta fileMeta) string {
	oldPath := filepath.Join(filesDir, filepath.Base(meta.File))
	targetName := filepath.Join(meta.ID, sanitizeFileName(meta.OriginalName))
	targetPath := filepath.Join(filesDir, targetName)

	if _, err := os.Stat(targetPath); err == nil {
		return targetName
	}
	info, err := os.Stat(oldPath)
	if err != nil || info.IsDir() {
		return meta.File
	}

	tmpPath := oldPath + ".migrating"
	if err := os.Rename(oldPath, tmpPath); err != nil {
		return meta.File
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o775); err != nil {
		_ = os.Rename(tmpPath, oldPath)
		return meta.File
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Rename(tmpPath, oldPath)
		return meta.File
	}
	return targetName
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

type webSocketConn struct {
	conn net.Conn
	rw   *bufio.ReadWriter
}

func acceptWebSocket(w http.ResponseWriter, r *http.Request) (*webSocketConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, fmt.Errorf("not websocket")
	}

	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		http.Error(w, "missing websocket key", http.StatusBadRequest)
		return nil, fmt.Errorf("missing websocket key")
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket not supported", http.StatusInternalServerError)
		return nil, fmt.Errorf("hijack not supported")
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}

	accept := webSocketAccept(key)
	if _, err := fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}

	return &webSocketConn{conn: conn, rw: rw}, nil
}

func webSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (c *webSocketConn) writeBinary(data []byte) error {
	return c.writeFrame(0x2, data)
}

func (c *webSocketConn) writeText(text string) error {
	return c.writeFrame(0x1, []byte(text))
}

func (c *webSocketConn) writeProgress(kind string, percent int, message string) error {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	data, err := json.Marshal(map[string]any{
		"type":    "progress",
		"kind":    kind,
		"percent": percent,
		"message": message,
	})
	if err != nil {
		return err
	}
	return c.writeText(string(data))
}

func (c *webSocketConn) writeClose(reason string) error {
	payload := []byte{0x03, 0xe8}
	if reason != "" {
		payload = append(payload, []byte(reason)...)
	}
	return c.writeFrame(0x8, payload)
}

func (c *webSocketConn) writeFrame(opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 65535:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(payload)))
		header = append(header, 127)
		header = append(header, size[:]...)
	}
	if _, err := c.rw.Write(header); err != nil {
		return err
	}
	if _, err := c.rw.Write(payload); err != nil {
		return err
	}
	return c.rw.Flush()
}

func (c *webSocketConn) readBinary(maxBytes int64) ([]byte, error) {
	for {
		opcode, payload, err := c.readFrame(maxBytes)
		if err != nil {
			return nil, err
		}
		switch opcode {
		case 0x2:
			return payload, nil
		case 0x8:
			return nil, fmt.Errorf("websocket closed")
		case 0x9:
			if err := c.writeFrame(0xA, payload); err != nil {
				return nil, err
			}
		}
	}
}

func (c *webSocketConn) readFrame(maxBytes int64) (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.rw, header); err != nil {
		return 0, nil, err
	}

	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	size := int64(header[1] & 0x7f)
	switch size {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(c.rw, b[:]); err != nil {
			return 0, nil, err
		}
		size = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(c.rw, b[:]); err != nil {
			return 0, nil, err
		}
		size = int64(binary.BigEndian.Uint64(b[:]))
	}
	if size < 0 || size > maxBytes {
		return 0, nil, fmt.Errorf("websocket payload too large")
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.rw, mask[:]); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, int(size))
	if _, err := io.ReadFull(c.rw, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func (c *webSocketConn) close() {
	_ = c.conn.Close()
}

func buildUploadsXLSX(metas []fileMeta) ([]byte, error) {
	var out bytes.Buffer
	zw := zip.NewWriter(&out)

	files := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
	<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
	<Default Extension="xml" ContentType="application/xml"/>
	<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
	<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
	<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`,
		"xl/workbook.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
	<sheets><sheet name="uploads" sheetId="1" r:id="rId1"/></sheets>
</workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
	<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`,
		"xl/worksheets/sheet1.xml": buildWorksheetXML(metas),
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			zw.Close()
			return nil, err
		}
		if _, err := io.WriteString(w, files[name]); err != nil {
			zw.Close()
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func buildWorksheetXML(metas []fileMeta) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	b.WriteString(`<row r="1">`)
	writeInlineCell(&b, "A", 1, "Название")
	writeInlineCell(&b, "B", 1, "Код")
	writeInlineCell(&b, "C", 1, "Дата добавления")
	b.WriteString(`</row>`)
	for i, meta := range metas {
		row := i + 2
		b.WriteString(fmt.Sprintf(`<row r="%d">`, row))
		writeInlineCell(&b, "A", row, nameWithoutPDF(meta.OriginalName))
		writeInlineCell(&b, "B", row, meta.ID)
		writeInlineCell(&b, "C", row, formatCreatedAtForXLSX(meta.CreatedAt))
		b.WriteString(`</row>`)
	}
	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}

func formatCreatedAtForXLSX(createdAt time.Time) string {
	if createdAt.IsZero() {
		return ""
	}
	return createdAt.Local().Format("15:04 02.01.2006")
}

func nameWithoutPDF(name string) string {
	if strings.EqualFold(filepath.Ext(name), ".pdf") {
		return strings.TrimSuffix(name, filepath.Ext(name))
	}
	return name
}

func normalizeFileTitle(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "\ufeff")
	name = nameWithoutPDF(name)
	return strings.ToLower(strings.TrimSpace(name))
}

func readXLSXFirstColumn(data []byte) ([]string, error) {
	rows, err := readXLSXRows(data)
	if err != nil {
		return nil, err
	}

	var names []string
	for i, row := range rows {
		value := strings.TrimSpace(row["A"])
		if i == 0 && strings.EqualFold(value, "Название") {
			continue
		}
		if value != "" {
			names = append(names, value)
		}
	}
	return names, nil
}

func readXLSXDeleteIDs(data []byte) ([]string, error) {
	rows, err := readXLSXRows(data)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	column := deleteIDColumn(rows[0])
	start := 0
	if column != "" {
		start = 1
	} else {
		column = "A"
	}

	seen := map[string]bool{}
	var ids []string
	for _, row := range rows[start:] {
		id, ok := publicIDFromLinkOrCode(row[column])
		if !ok || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

func deleteIDColumn(header map[string]string) string {
	for _, col := range []string{"B", "A", "C"} {
		value := strings.TrimSpace(header[col])
		if strings.EqualFold(value, "Ссылка") || strings.EqualFold(value, "Код") {
			return col
		}
	}
	return ""
}

func publicIDFromLinkOrCode(value string) (string, bool) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "\ufeff"))
	if value == "" {
		return "", false
	}
	if validDeletePublicID(value) {
		return value, true
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", false
	}
	path := strings.Trim(parsed.EscapedPath(), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}
	if parts[0] == "p" && len(parts) > 1 {
		parts = parts[1:]
	}
	id, err := url.PathUnescape(parts[0])
	if err != nil || !validDeletePublicID(id) {
		return "", false
	}
	return id, true
}

func validDeletePublicID(id string) bool {
	if len(id) != publicIDLength {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func readXLSXRows(data []byte) ([]map[string]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	shared, err := readXLSXSharedStrings(zr)
	if err != nil {
		return nil, err
	}

	sheet, err := readXLSXPart(zr, "xl/worksheets/sheet1.xml")
	if err != nil {
		return nil, err
	}

	decoder := xml.NewDecoder(strings.NewReader(sheet))
	rowsByIndex := map[int]map[string]string{}
	var rowNumbers []int
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "c" {
			continue
		}

		ref := xmlAttr(start, "r")
		col := cellColumn(ref)
		row := cellRow(ref)

		value, err := readXLSXCell(decoder, xmlAttr(start, "t"), shared)
		if err != nil {
			return nil, err
		}
		value = strings.TrimSpace(value)
		if col == "" || row == 0 || value == "" {
			continue
		}
		if rowsByIndex[row] == nil {
			rowsByIndex[row] = map[string]string{}
			rowNumbers = append(rowNumbers, row)
		}
		rowsByIndex[row][col] = value
	}
	sort.Ints(rowNumbers)
	rows := make([]map[string]string, 0, len(rowNumbers))
	for _, row := range rowNumbers {
		rows = append(rows, rowsByIndex[row])
	}
	return rows, nil
}

func readXLSXSharedStrings(zr *zip.Reader) ([]string, error) {
	data, err := readXLSXPart(zr, "xl/sharedStrings.xml")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	decoder := xml.NewDecoder(strings.NewReader(data))
	var values []string
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "si" {
			continue
		}
		value, err := readSharedString(decoder)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func readSharedString(decoder *xml.Decoder) (string, error) {
	var b strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", err
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local == "t" {
				var value string
				if err := decoder.DecodeElement(&value, &t); err != nil {
					return "", err
				}
				b.WriteString(value)
			}
		case xml.EndElement:
			if t.Name.Local == "si" {
				return b.String(), nil
			}
		}
	}
}

func readXLSXCell(decoder *xml.Decoder, cellType string, shared []string) (string, error) {
	var value string
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", err
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local == "t" || t.Name.Local == "v" {
				var part string
				if err := decoder.DecodeElement(&part, &t); err != nil {
					return "", err
				}
				value += part
			}
		case xml.EndElement:
			if t.Name.Local == "c" {
				if cellType == "s" {
					var idx int
					if _, err := fmt.Sscanf(strings.TrimSpace(value), "%d", &idx); err == nil && idx >= 0 && idx < len(shared) {
						return shared[idx], nil
					}
				}
				return value, nil
			}
		}
	}
}

func skipXMLCell(decoder *xml.Decoder) error {
	depth := 1
	for depth > 0 {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch token.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		}
	}
	return nil
}

func readXLSXPart(zr *zip.Reader, name string) (string, error) {
	for _, file := range zr.File {
		if file.Name != name {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()
		data, err := io.ReadAll(rc)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	return "", os.ErrNotExist
}

func xmlAttr(start xml.StartElement, name string) string {
	for _, attr := range start.Attr {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

func cellColumn(ref string) string {
	var b strings.Builder
	for _, r := range ref {
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		if r < 'A' || r > 'Z' {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func cellRow(ref string) int {
	var row int
	for _, r := range ref {
		if r < '0' || r > '9' {
			continue
		}
		row = row*10 + int(r-'0')
	}
	return row
}

func writeInlineCell(b *strings.Builder, col string, row int, value string) {
	b.WriteString(fmt.Sprintf(`<c r="%s%d" t="inlineStr"><is><t>`, col, row))
	_ = xml.EscapeText(b, []byte(value))
	b.WriteString(`</t></is></c>`)
}

const js = `(() => {
    const pdfViewer = document.querySelector("[data-pdf-viewer]");
    if (pdfViewer) {
        const status = document.querySelector("[data-pdf-status]");
        let resizeTimer = 0;
        const setStatus = (message) => {
            if (status) {
                status.textContent = message;
            }
        };

        const renderPDF = async () => {
            if (!window.pdfjsLib) {
                setStatus("Не удалось загрузить просмотрщик PDF.");
                return;
            }

            const pdfURL = pdfViewer.dataset.pdfUrl;
            window.pdfjsLib.GlobalWorkerOptions.workerSrc = "https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js";

            const pdf = await window.pdfjsLib.getDocument(pdfURL).promise;
            setStatus("Страниц: " + pdf.numPages);
            pdfViewer.querySelectorAll(".pdf-page").forEach((page) => page.remove());

            for (let pageNumber = 1; pageNumber <= pdf.numPages; pageNumber += 1) {
                const page = await pdf.getPage(pageNumber);
                const baseViewport = page.getViewport({ scale: 1 });
                const availableWidth = Math.max(320, pdfViewer.clientWidth);
                const scale = availableWidth / baseViewport.width;
                const viewport = page.getViewport({ scale });
                const outputScale = Math.min(Math.max(window.devicePixelRatio || 1, 2) * 2, 4);

                const canvas = document.createElement("canvas");
                canvas.className = "pdf-page";
                canvas.width = Math.floor(viewport.width * outputScale);
                canvas.height = Math.floor(viewport.height * outputScale);
                canvas.style.width = Math.floor(viewport.width) + "px";
                canvas.style.height = Math.floor(viewport.height) + "px";

                const context = canvas.getContext("2d");
                context.setTransform(outputScale, 0, 0, outputScale, 0, 0);
                pdfViewer.appendChild(canvas);

                await page.render({ canvasContext: context, viewport }).promise;
            }

            if (status) {
                status.remove();
            }
        };

        renderPDF().catch(() => {
            setStatus("Не удалось открыть PDF. Попробуйте скачать файл.");
        });

        window.addEventListener("resize", () => {
            window.clearTimeout(resizeTimer);
            resizeTimer = window.setTimeout(() => {
                renderPDF().catch(() => {
                    setStatus("Не удалось открыть PDF. Попробуйте скачать файл.");
                });
            }, 250);
        });
    }

    const progress = document.querySelector("[data-progress]");
    const progressTitle = document.querySelector("[data-progress-title]");
    const progressPercent = document.querySelector("[data-progress-percent]");
    const progressBar = document.querySelector("[data-progress-bar]");
    const progressMessage = document.querySelector("[data-progress-message]");
    const csrfToken = document.querySelector("meta[name=csrf-token]")?.content || "";

    const showProgress = (title, percent, message) => {
        if (!progress) {
            return;
        }
        progress.hidden = false;
        progressTitle.textContent = title;
        progressPercent.textContent = percent + "%";
        progressBar.style.width = percent + "%";
        progressMessage.textContent = message || "";
    };

    const wsURL = (path) => {
        const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
        return scheme + "//" + window.location.host + path;
    };

    const withCSRF = (path) => {
        if (!csrfToken) {
            return path;
        }
        const separator = path.includes("?") ? "&" : "?";
        return path + separator + "csrf_token=" + encodeURIComponent(csrfToken);
    };

    const handleProgressMessage = (event, fallbackTitle) => {
        if (typeof event.data !== "string") {
            return false;
        }
        try {
            const payload = JSON.parse(event.data);
            if (payload.type === "progress") {
                showProgress(fallbackTitle, payload.percent || 0, payload.message || "");
                return true;
            }
        } catch (_) {
        }
        return false;
    };

    const uploadForm = document.querySelector("[data-upload-form]");
    if (uploadForm) {
        uploadForm.addEventListener("submit", (event) => {
            event.preventDefault();

            const button = uploadForm.querySelector("button[type=submit]");
            const input = uploadForm.querySelector("input[type=file]");
            const originalText = button.textContent;

            if (!input || !input.files || input.files.length === 0) {
                return;
            }

            button.disabled = true;
            button.textContent = "Загрузка...";
            showProgress("Загрузка файлов", 0, "Готовим отправку...");

            const request = new XMLHttpRequest();
            request.open("POST", uploadForm.action);

            request.upload.onprogress = (event) => {
                if (!event.lengthComputable) {
                    showProgress("Загрузка файлов", 0, "Отправляем файлы...");
                    return;
                }
                const percent = Math.min(99, Math.round((event.loaded / event.total) * 100));
                showProgress("Загрузка файлов", percent, "Отправлено " + percent + "%");
            };

            request.onload = () => {
                if (request.status >= 200 && request.status < 300) {
                    showProgress("Загрузка файлов", 100, "Файлы отправлены. Открываем результат...");
                    document.open();
                    document.write(request.responseText);
                    document.close();
                    return;
                }
                button.disabled = false;
                button.textContent = originalText;
                showProgress("Загрузка файлов", 0, "Не удалось загрузить файлы.");
            };

            request.onerror = () => {
                button.disabled = false;
                button.textContent = originalText;
                showProgress("Загрузка файлов", 0, "Соединение оборвалось во время загрузки.");
            };

            request.send(new FormData(uploadForm));
        });
    }

    const exportButton = document.querySelector("[data-export-xlsx]");
    if (exportButton) {
        exportButton.addEventListener("click", () => {
            const originalText = exportButton.textContent;
            exportButton.disabled = true;
            exportButton.textContent = "Выгрузка...";
            showProgress("Выгрузка XLSX", 0, "Начинаем...");

            const socket = new WebSocket(wsURL(withCSRF("/ws/uploads.xlsx")));
            socket.binaryType = "arraybuffer";

            socket.onmessage = (event) => {
                if (handleProgressMessage(event, "Выгрузка XLSX")) {
                    return;
                }
                const blob = new Blob([event.data], {
                    type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                });
                const link = document.createElement("a");
                link.href = URL.createObjectURL(blob);
                link.download = "uploads.xlsx";
                document.body.appendChild(link);
                link.click();
                URL.revokeObjectURL(link.href);
                link.remove();
            };

            socket.onclose = () => {
                exportButton.disabled = false;
                exportButton.textContent = originalText;
            };

            socket.onerror = () => {
                exportButton.disabled = false;
                exportButton.textContent = originalText;
                alert("Не удалось выгрузить XLSX.");
            };
        });
    }

    const deleteForm = document.querySelector("[data-delete-form]");
    if (deleteForm) {
        deleteForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const input = deleteForm.querySelector("input[type=file]");
            const file = input && input.files && input.files[0];
            if (!file) {
                return;
            }

            const button = deleteForm.querySelector("button[type=submit]");
            const originalText = button.textContent;
            button.disabled = true;
            button.textContent = "Удаление...";
            showProgress("Удаление по XLSX", 0, "Подключаемся...");

            const socket = new WebSocket(wsURL(withCSRF("/ws/delete.xlsx")));
            socket.binaryType = "arraybuffer";

            socket.onopen = () => {
                showProgress("Удаление по XLSX", 5, "Отправляем XLSX...");
                socket.send(file);
            };

            socket.onmessage = (event) => {
                handleProgressMessage(event, "Удаление по XLSX");
            };

            socket.onclose = () => {
                button.disabled = false;
                button.textContent = originalText;
                if (progressBar && progressBar.style.width === "100%") {
                    window.setTimeout(() => window.location.reload(), 700);
                }
            };

            socket.onerror = () => {
                button.disabled = false;
                button.textContent = originalText;
                alert("Не удалось удалить файлы по XLSX.");
            };
        });
    }
})();`

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
    min-width: 900px;
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

.app-main {
    min-width: 0;
}

.topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    min-height: 64px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    padding: 12px 28px;
}

.topbar .btn {
    width: auto;
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

.not-found-screen {
    display: grid;
    min-height: 100vh;
    place-items: center;
    padding: 24px;
}

.not-found-panel {
    width: min(100%, 460px);
    text-align: center;
}

.not-found-panel p {
    margin: 0 0 10px;
    color: var(--muted);
    font-size: 14px;
    font-weight: 700;
}

.not-found-panel h1 {
    margin: 0 0 22px;
    color: #111827;
    font-size: 30px;
    line-height: 1.2;
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

.search-form {
    max-width: 920px;
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto auto;
    gap: 10px;
    margin-bottom: 14px;
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

.tools-card {
    margin-bottom: 14px;
}

.progress-panel {
    max-width: 920px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    padding: 14px;
    margin-bottom: 14px;
}

.progress-top {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    color: #111827;
    font-size: 14px;
    line-height: 1.4;
}

.progress-track {
    height: 10px;
    overflow: hidden;
    border-radius: 999px;
    background: var(--secondary);
    margin-top: 10px;
}

.progress-bar {
    width: 0;
    height: 100%;
    border-radius: inherit;
    background: var(--primary);
    transition: width 160ms ease;
}

.progress-panel p {
    margin: 10px 0 0;
    color: var(--muted);
    font-size: 13px;
    line-height: 1.45;
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
    display: grid;
    justify-items: center;
    gap: 14px;
}

.pdf-status {
    width: 100%;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    color: var(--muted);
    padding: 18px;
    text-align: center;
}

.pdf-page {
    display: block;
    max-width: 100%;
    height: auto;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--surface);
    box-shadow: 0 10px 26px rgba(15, 23, 42, 0.10);
}`
