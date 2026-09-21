package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ChaosChild/cavet/internal/store"
)

type drift struct {
	diskOnlyFindings   []string // on disk, absent from replay: the log cannot regenerate them
	replayOnlyFindings []string // in replay, absent on disk: lost rows, log-derivable
	verdictChanged     []string
	statusChanged      []string
	baselineChanged    []string
	diskOnlyItems      []string
	replayOnlyItems    []string
}

func (d drift) found() bool {
	return len(d.diskOnlyFindings)+len(d.replayOnlyFindings)+len(d.verdictChanged)+
		len(d.statusChanged)+len(d.baselineChanged)+len(d.diskOnlyItems)+len(d.replayOnlyItems) > 0
}

// safeToFix reports whether every drift class is log-derivable. Disk-only
// findings or items mean the disk knows something the log does not; fix
// refuses rather than silently delete them.
func (d drift) safeToFix() bool {
	return len(d.diskOnlyFindings) == 0 && len(d.diskOnlyItems) == 0
}

func shortIDs(ids []string) string {
	const maxShown = 10
	if len(ids) > maxShown {
		return strings.Join(ids[:maxShown], ", ") + fmt.Sprintf(" (+%d more)", len(ids)-maxShown)
	}
	return strings.Join(ids, ", ")
}

func (d drift) String() string {
	var b strings.Builder
	say := func(n int, label, ids string) {
		if n > 0 {
			fmt.Fprintf(&b, "  %s: %d (%s)\n", label, n, ids)
		}
	}
	say(len(d.replayOnlyFindings), "findings in log but missing on disk", shortIDs(d.replayOnlyFindings))
	say(len(d.diskOnlyFindings), "findings on disk but not in log replay", shortIDs(d.diskOnlyFindings))
	say(len(d.verdictChanged), "verdicts differing from replay", shortIDs(d.verdictChanged))
	say(len(d.statusChanged), "statuses differing from replay", shortIDs(d.statusChanged))
	say(len(d.baselineChanged), "in_baseline flags differing from replay", shortIDs(d.baselineChanged))
	say(len(d.replayOnlyItems), "items in log but missing on disk", shortIDs(d.replayOnlyItems))
	say(len(d.diskOnlyItems), "items on disk but not in log replay", shortIDs(d.diskOnlyItems))
	return b.String()
}

func verdictText(f *store.Finding) string {
	if f.Verdict == nil {
		return ""
	}
	return f.Verdict.Verdict + "\x00" + f.Verdict.Reason
}

// shortFP renders the 8-hex drift-report prefix (the brief's diff tests
// pin the length; full fingerprints stay in `cavet log` output).
func shortFP(fp string) string {
	if len(fp) > 8 {
		return fp[:8]
	}
	return fp
}

func diffState(disk, replay *store.State) drift {
	var d drift
	diskFP := map[string]*store.Finding{}
	for _, f := range disk.Findings {
		diskFP[f.Fingerprint] = f
	}
	replayFP := map[string]*store.Finding{}
	for _, f := range replay.Findings {
		replayFP[f.Fingerprint] = f
		diskF, ok := diskFP[f.Fingerprint]
		if !ok {
			d.replayOnlyFindings = append(d.replayOnlyFindings, shortFP(f.Fingerprint))
			continue
		}
		if diskF.Status != f.Status {
			d.statusChanged = append(d.statusChanged, shortFP(f.Fingerprint))
		}
		if verdictText(diskF) != verdictText(f) {
			d.verdictChanged = append(d.verdictChanged, shortFP(f.Fingerprint))
		}
		if diskF.InBaseline != f.InBaseline {
			d.baselineChanged = append(d.baselineChanged, shortFP(f.Fingerprint))
		}
	}
	for fp := range diskFP {
		if _, ok := replayFP[fp]; !ok {
			d.diskOnlyFindings = append(d.diskOnlyFindings, shortFP(fp))
		}
	}
	replayItems := map[string]bool{}
	for _, it := range replay.Items {
		replayItems[it.ID] = true
		if !diskHasItem(disk, it.ID) {
			d.replayOnlyItems = append(d.replayOnlyItems, it.ID)
		}
	}
	for _, it := range disk.Items {
		if !replayItems[it.ID] {
			d.diskOnlyItems = append(d.diskOnlyItems, it.ID)
		}
	}
	return d
}

func diskHasItem(disk *store.State, id string) bool {
	for _, it := range disk.Items {
		if it.ID == id {
			return true
		}
	}
	return false
}

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Replay the log and diff it against state/, report only",
		RunE:  runDoctorReport,
	}
	fix := &cobra.Command{
		Use:   "fix",
		Short: "Repair the drift doctor reports, log-derivable classes only",
		RunE:  runDoctorFix,
	}
	cmd.AddCommand(fix)
	return cmd
}

// replayToScratch stages the replay inputs (log/ and baseline.json) into a
// temp dir and replays there; the real .cavet/ is never written.
func replayToScratch(s *store.Store) (evs int, replayed *store.State, err error) {
	evsList, err := s.ReadLog()
	if err != nil {
		return 0, nil, err
	}
	tmp, err := os.MkdirTemp("", "cavet-doctor-")
	if err != nil {
		return 0, nil, err
	}
	if err := copyForReplay(s, tmp); err != nil {
		os.RemoveAll(tmp)
		return 0, nil, err
	}
	// scratch replay writes into tmp only; remove it once the fold is done
	defer os.RemoveAll(tmp) //nolint: errcheck // scratch dir
	st, err := (&store.Store{Root: s.Root, Cavet: tmp}).Rebuild()
	if err != nil {
		return 0, nil, fmt.Errorf("log replay failed: %w", err)
	}
	return len(evsList), st, nil
}

func printReport(disk *store.State, replayed *store.State, d drift) {
	fmt.Printf("doctor: findings %d on disk vs %d replayed, items %d on disk vs %d replayed\n",
		len(disk.Findings), len(replayed.Findings), len(disk.Items), len(replayed.Items))
	if !d.found() {
		fmt.Println("drift: none")
		return
	}
	fmt.Println("drift:")
	fmt.Print(d.String())
}

func runDoctorReport(_ *cobra.Command, _ []string) error {
	s, err := openStore()
	if err != nil {
		return err
	}
	disk, err := s.LoadState()
	if err != nil {
		return fail(err.Error())
	}
	_, replayed, err := replayToScratch(s)
	if err != nil {
		return fail(err.Error())
	}
	d := diffState(disk, replayed)
	printReport(disk, replayed, d)
	if d.found() {
		// drift is the informational findings-present exit (spec §4, AXI 6):
		// code 1 deliberately, never fail() which hardwires 2.
		return &exitErr{code: 1, msg: "state/ disagrees with log/ (informational exit 1); 'cavet doctor fix' repairs log-derivable drift, 'cavet rebuild' rewrites unconditionally"}
	}
	return nil
}

func runDoctorFix(_ *cobra.Command, _ []string) error {
	s, err := openStore()
	if err != nil {
		return err
	}
	return doctorFixStore(s)
}

// doctorFixStore is the doctor-fix body, split from the cobra runner so tests
// exercise it against a scratch store directly. Report path, refusal path,
// and the real write under the store lock all live here.
func doctorFixStore(s *store.Store) error {
	disk, err := s.LoadState()
	if err != nil {
		return fail(err.Error())
	}
	_, replayed, err := replayToScratch(s)
	if err != nil {
		return fail(err.Error())
	}
	d := diffState(disk, replayed)
	if !d.found() {
		fmt.Println("drift: none, nothing to fix")
		return nil
	}
	if !d.safeToFix() {
		printReport(disk, replayed, d)
		return &exitErr{code: 1, msg: "doctor fix refused: findings or items on disk are absent from the log; the log cannot regenerate them. Review the list above by hand (cavet raise can re-record intentional items)"}
	}
	rel, err := s.Lock()
	if err != nil {
		return fail(err.Error())
	}
	defer rel()
	if err := s.WriteState(replayed); err != nil {
		return fail(err.Error())
	}
	fmt.Printf("fixed: rewrote state/ from the log (%s)\n", strings.TrimSpace(strings.ReplaceAll(d.String(), "\n", "; ")))
	fmt.Println("note: last_seen values decayed to log-derived ones; a fresh scan refreshes them")
	return nil
}

func copyForReplay(s *store.Store, tmp string) error {
	if err := os.MkdirAll(filepath.Join(tmp, "log"), 0o755); err != nil {
		return err
	}
	srcs, _ := filepath.Glob(filepath.Join(s.Cavet, "log", "events-*.jsonl"))
	for _, src := range srcs {
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tmp, "log", filepath.Base(src)), b, 0o644); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(tmp, "state"), 0o755); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(s.Cavet, "state", "baseline.json"))
	if os.IsNotExist(err) {
		return nil // no baseline yet: replay runs without one, same as rebuild
	}
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(tmp, "state", "baseline.json"), b, 0o644)
}
