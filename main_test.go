package main

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRandomPublicID(t *testing.T) {
	id, err := randomPublicID()
	if err != nil {
		t.Fatalf("randomPublicID() error = %v", err)
	}
	if len(id) != publicIDLength {
		t.Fatalf("randomPublicID() length = %d, want %d", len(id), publicIDLength)
	}
	for _, r := range id {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789", r) {
			t.Fatalf("randomPublicID() contains unexpected rune %q in %q", r, id)
		}
	}
}

func TestBuildUploadsXLSX(t *testing.T) {
	data, err := buildUploadsXLSX([]fileMeta{
		{ID: "a1b2c", OriginalName: "report.pdf", CreatedAt: time.Now()},
	})
	if err != nil {
		t.Fatalf("buildUploadsXLSX() error = %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("xlsx is not a zip archive: %v", err)
	}

	worksheet := readZipFile(t, zr, "xl/worksheets/sheet1.xml")
	if !strings.Contains(worksheet, ">Название<") {
		t.Fatalf("worksheet does not contain name header: %s", worksheet)
	}
	if !strings.Contains(worksheet, ">Код<") {
		t.Fatalf("worksheet does not contain code header: %s", worksheet)
	}
	if !strings.Contains(worksheet, ">report<") {
		t.Fatalf("worksheet does not contain PDF name without extension: %s", worksheet)
	}
	if !strings.Contains(worksheet, ">a1b2c<") {
		t.Fatalf("worksheet does not contain public ID: %s", worksheet)
	}
}

func TestZipPDFEntriesFindsNestedPDFs(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{
		"root.pdf",
		"level-1/level-2/level-3/deep.pdf",
		"level-1/not-pdf.txt",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte("%PDF test")); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("read zip: %v", err)
	}

	files := zipPDFEntries(zr.File)
	if len(files) != 2 {
		t.Fatalf("zipPDFEntries() length = %d, want 2", len(files))
	}
	if files[0].Name != "root.pdf" || files[1].Name != "level-1/level-2/level-3/deep.pdf" {
		t.Fatalf("zipPDFEntries() = [%s, %s], want nested PDFs", files[0].Name, files[1].Name)
	}
}

func TestPublicURLUsesConfiguredBaseURL(t *testing.T) {
	t.Setenv("APP_BASE_URL", "https://example.com/")

	got := publicURL(&http.Request{Host: "localhost:8010"}, fileMeta{ID: "a1b2c"})
	want := "https://example.com/a1b2c"
	if got != want {
		t.Fatalf("publicURL() = %q, want %q", got, want)
	}
}

func TestPublicURLAddsSchemeToConfiguredHost(t *testing.T) {
	t.Setenv("APP_BASE_URL", "example.com/")

	got := publicURL(&http.Request{Host: "localhost:8010"}, fileMeta{ID: "a1b2c"})
	want := "https://example.com/a1b2c"
	if got != want {
		t.Fatalf("publicURL() = %q, want %q", got, want)
	}
}

func TestPublicURLFallsBackToRequestHost(t *testing.T) {
	t.Setenv("APP_BASE_URL", "")

	got := publicURL(&http.Request{Host: "localhost:8010"}, fileMeta{ID: "a1b2c"})
	want := "http://localhost:8010/a1b2c"
	if got != want {
		t.Fatalf("publicURL() = %q, want %q", got, want)
	}
}

func TestValidCSRFRequiresSessionToken(t *testing.T) {
	const sessionToken = "test-session"
	sessions.set(sessionToken)
	defer sessions.delete(sessionToken)

	req := &http.Request{URL: &url.URL{}, Header: http.Header{}}
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionToken})
	token := csrfToken(req)
	if token == "" {
		t.Fatal("csrfToken() returned empty token")
	}

	req.URL.RawQuery = "csrf_token=" + url.QueryEscape(token)
	if !validCSRF(req) {
		t.Fatal("validCSRF() rejected valid token")
	}

	req.URL.RawQuery = "csrf_token=bad"
	if validCSRF(req) {
		t.Fatal("validCSRF() accepted invalid token")
	}
}

func TestReadXLSXFirstColumn(t *testing.T) {
	data, err := buildUploadsXLSX([]fileMeta{
		{ID: "a1b2c", OriginalName: "report.pdf", CreatedAt: time.Now()},
		{ID: "d4e5f", OriginalName: "invoice.pdf", CreatedAt: time.Now()},
	})
	if err != nil {
		t.Fatalf("buildUploadsXLSX() error = %v", err)
	}

	names, err := readXLSXFirstColumn(data)
	if err != nil {
		t.Fatalf("readXLSXFirstColumn() error = %v", err)
	}

	want := []string{"report", "invoice"}
	if len(names) != len(want) {
		t.Fatalf("readXLSXFirstColumn() length = %d, want %d (%v)", len(names), len(want), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("readXLSXFirstColumn()[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func readZipFile(t *testing.T, zr *zip.Reader, name string) string {
	t.Helper()

	for _, file := range zr.File {
		if file.Name != name {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("open zip file %s: %v", name, err)
		}
		defer rc.Close()

		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read zip file %s: %v", name, err)
		}
		return string(data)
	}

	t.Fatalf("zip file %s not found", name)
	return ""
}
