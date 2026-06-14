package checksec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// ParseProcMaps reads a /proc/<pid>/maps stream and returns the unique
// backing-file paths in first-seen order. Anonymous mappings, pseudo-paths
// ([vdso], [heap], …), memfd, and deleted-on-disk mappings are excluded.
//
// maps format (proc(5)):
//
//	address           perms offset  dev   inode   pathname
//	7f0000000000-…    r-xp  0000…   08:01 456     /usr/lib/libc.so.6
func ParseProcMaps(r io.Reader) ([]string, error) {
	var paths []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	// Raise the default 64KiB token limit so deep paths don't trip
	// bufio.ErrTooLong and silently truncate the scan.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		// The pathname column starts after 5 fixed whitespace-separated fields
		// (addr, perms, offset, dev, inode). Those five never contain spaces;
		// the pathname may. Skip past the 5th field's end, then take the rest.
		path := mapsPathname(line)
		if path == "" || !strings.HasPrefix(path, "/") {
			continue // anonymous, [vdso], [heap], etc.
		}
		if strings.HasSuffix(path, " (deleted)") || strings.HasPrefix(path, "/memfd:") {
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	return paths, sc.Err()
}

// mapsPathname extracts the pathname (6th) column from a /proc/<pid>/maps line,
// independent of how many whitespace characters separate the first five fields.
// The first five fields contain no whitespace; the pathname may.
func mapsPathname(line string) string {
	i, fields := 0, 0
	for i < len(line) && fields < 5 {
		// skip leading whitespace
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		// consume one field
		start := i
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		if i > start {
			fields++
		} else {
			break
		}
	}
	if fields < 5 {
		return ""
	}
	// skip whitespace before pathname
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	return strings.TrimRight(line[i:], " \t")
}

// ProcLibs returns the unique mapped-file paths for pid, or an error if
// /proc/<pid>/maps is unreadable (no procfs, no such PID, permission denied).
func ProcLibs(pid int) ([]string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseProcMaps(f)
}
