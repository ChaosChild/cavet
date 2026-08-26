package store

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ChaosChild/cavet/internal/events"
)

// ParseError names the offending log line; the log is the source of truth, so
// repair is manual and never silent (artefacts §8).
type ParseError struct {
	File string
	Line int
	Err  error
}

func (p *ParseError) Error() string {
	return fmt.Sprintf("%s:%d: %v (log is source of truth; repair manually)", p.File, p.Line, p.Err)
}

// Enriched carries provenance through replay.
type Enriched struct {
	events.Event
	File string
	Raw  []byte // original line bytes, byte-preserved for unknown kinds
}

// Append writes one event as one \n-terminated line into the monthly file of
// its timestamp (artefacts §§2, 7.2).
func (s *Store) Append(e events.Event) error {
	name := "events-" + e.TS.UTC().Format("2006-01") + ".jsonl"
	f, err := os.OpenFile(filepath.Join(s.Cavet, "log", name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(events.Canonical(e), '\n'))
	return err
}

// ReadLog parses every log file in chronological (lexicographic) order.
// Corruption policy per artefacts §8: malformed lines are hard errors; a
// trailing partial line — the crash-mid-append case — warns and is ignored;
// a partial line with data after it is corruption, not a crash tail.
func (s *Store) ReadLog() ([]Enriched, error) {
	files, err := s.logGlob()
	if err != nil {
		return nil, err
	}
	var out []Enriched
	for _, file := range files {
		evs, err := readOne(file)
		if err != nil {
			return out, err
		}
		out = append(out, evs...)
	}
	return out, nil
}

func readOne(file string) ([]Enriched, error) {
	fh, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	var out []Enriched
	var pending *ParseError // partial line awaiting proof it is the file tail
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if pending != nil {
			return out, pending // something followed it: real corruption
		}
		ev, err := events.Decode(line)
		if err != nil {
			if isPartialLine(err) && sc.Err() == nil {
				pending = &ParseError{File: filepath.Base(file), Line: n, Err: err}
				continue
			}
			return out, &ParseError{File: filepath.Base(file), Line: n, Err: err}
		}
		out = append(out, Enriched{Event: ev, File: filepath.Base(file),
			Raw: append([]byte(nil), line...)}) // scanner reuses its buffer
	}
	if err := sc.Err(); err != nil {
		return out, &ParseError{File: filepath.Base(file), Line: n + 1, Err: err}
	}
	if pending != nil {
		fmt.Fprintf(os.Stderr, "warning: %s:%d: trailing partial line ignored\n", pending.File, pending.Line)
	}
	return out, nil
}

func isPartialLine(err error) bool {
	return strings.Contains(err.Error(), "unexpected end of JSON input")
}

func (s *Store) logGlob() ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(s.Cavet, "log", "events-*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches) // lexicographic == chronological
	return matches, nil
}
