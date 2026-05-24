package main

import (
	"archive/zip"
	"bytes"
	"io"
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
	if !strings.Contains(worksheet, ">report<") {
		t.Fatalf("worksheet does not contain PDF name without extension: %s", worksheet)
	}
	if !strings.Contains(worksheet, ">a1b2c<") {
		t.Fatalf("worksheet does not contain public ID: %s", worksheet)
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
