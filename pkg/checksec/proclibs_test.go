package checksec

import (
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

// TestParseProcMaps verifies extraction of unique mapped-file paths from a
// /proc/<pid>/maps stream. Anonymous mappings, [vdso]/[heap]/etc., and
// duplicate paths are excluded.
func TestParseProcMaps(t *testing.T) {
	const sample = `55a1c0000000-55a1c0001000 r--p 00000000 08:01 123 /usr/bin/cat
55a1c0001000-55a1c0002000 r-xp 00001000 08:01 123 /usr/bin/cat
7f0000000000-7f0000001000 r--p 00000000 08:01 456 /usr/lib/libc.so.6
7f0000001000-7f0000100000 r-xp 00001000 08:01 456 /usr/lib/libc.so.6
7f0000200000-7f0000201000 r--p 00000000 08:01 789 /usr/lib/ld-linux-x86-64.so.2
7f0000300000-7f0000301000 rw-p 00000000 00:00 0
7f0000400000-7f0000401000 r-xp 00000000 00:00 0                          [vdso]
7f0000500000-7f0000501000 r--p 00000000 08:01 999 /usr/lib/with spaces/lib.so
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
7f0000600000-7f0000601000 r--p 00000000 08:01 111 /memfd:foo (deleted)
`
	got, err := ParseProcMaps(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("ParseProcMaps: %v", err)
	}
	want := []string{
		"/usr/bin/cat",
		"/usr/lib/libc.so.6",
		"/usr/lib/ld-linux-x86-64.so.2",
		"/usr/lib/with spaces/lib.so",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseProcMaps() = %v\nwant %v", got, want)
	}
}

// TestParseProcMaps_VariableWhitespace exercises the real /proc/<pid>/maps
// column layout where the inode and pathname columns are separated by multiple
// spaces (right-aligned inode). SplitN(" ", 6) would treat each space as a
// delimiter and shift the pathname into the wrong field.
func TestParseProcMaps_VariableWhitespace(t *testing.T) {
	const sample = "" +
		"7f9c00000000-7f9c00026000 r--p 00000000 08:02 12345678                   /usr/lib64/libc.so.6\n" +
		"7f9c00200000-7f9c00201000 r-xp 00000000 00:00 0                          [vdso]\n" +
		"7f9c00300000-7f9c00301000 r--p 00000000 08:02 999      /opt/with spaces/lib.so\n" +
		"7f9c00400000-7f9c00401000 rw-p 00000000 00:00 0\n" + // anonymous, trailing space then nothing
		"7f9c00500000-7f9c00501000 r--p 00000000 08:02 1\t/usr/lib/tab.so\n" // tab separator
	got, _ := ParseProcMaps(strings.NewReader(sample))
	want := []string{
		"/usr/lib64/libc.so.6",
		"/opt/with spaces/lib.so",
		"/usr/lib/tab.so",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseProcMaps() = %#v\nwant %#v", got, want)
	}
}

func TestParseProcMaps_Empty(t *testing.T) {
	if got, _ := ParseProcMaps(strings.NewReader("")); got != nil {
		t.Errorf("ParseProcMaps(empty) = %v, want nil", got)
	}
}

// TestParseProcMaps_PropagatesScanError guards the PR-review finding: a read
// error from the underlying reader must surface, not silently truncate the
// result set.
func TestParseProcMaps_PropagatesScanError(t *testing.T) {
	r := io.MultiReader(
		strings.NewReader("0-1 r--p 0 0:0 1 /lib/a.so\n"),
		iotest.ErrReader(io.ErrUnexpectedEOF),
	)
	_, err := ParseProcMaps(r)
	if err == nil {
		t.Fatal("expected error from failing reader, got nil")
	}
}

// TestParseProcMaps_LongLine asserts the scanner buffer is large enough that a
// realistic-but-long maps line (deep path) doesn't trip bufio.ErrTooLong.
func TestParseProcMaps_LongLine(t *testing.T) {
	long := "0-1 r--p 0 0:0 1 /" + strings.Repeat("a", 100_000) + "/x.so\n"
	got, err := ParseProcMaps(strings.NewReader(long))
	if err != nil {
		t.Fatalf("ParseProcMaps long line: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 path from long line, got %d", len(got))
	}
}

func TestProcLibs_ErrorPath(t *testing.T) {
	// PID -1 has no /proc entry on any platform.
	if _, err := ProcLibs(-1); err == nil {
		t.Error("ProcLibs(-1) returned nil error")
	}
}

func TestParseProcMaps_PreservesFirstSeenOrder(t *testing.T) {
	const sample = `0-1 r--p 0 0:0 1 /b
1-2 r--p 0 0:0 2 /a
2-3 r--p 0 0:0 1 /b
`
	got, _ := ParseProcMaps(strings.NewReader(sample))
	want := []string{"/b", "/a"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (first-seen order)", got, want)
	}
}
