package banner_test

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/kiurakku/GramFuzz/internal/banner"
)

func TestCompact(t *testing.T) {
	got := banner.Compact()
	if !strings.Contains(got, "GramFuzz") {
		t.Fatalf("expected brand name in compact banner, got %q", got)
	}
}

func TestPrint(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	banner.Print()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "GramFuzz") {
		t.Fatal("banner output missing GramFuzz")
	}
	if !strings.Contains(out, banner.Version) {
		t.Fatalf("banner output missing version %s", banner.Version)
	}
}
