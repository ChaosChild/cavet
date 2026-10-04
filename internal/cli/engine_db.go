package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ChaosChild/cavet/internal/config"
	"github.com/ChaosChild/cavet/internal/engineclient"
	"github.com/ChaosChild/cavet/internal/events"
	"github.com/ChaosChild/cavet/internal/store"
)

// newEngineDBCmd wires `cavet engine update-db`.
func newEngineDBCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update-db",
		Short: "Refresh advisory databases in the engine volumes (host-side fetch, staged swap)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runEngineUpdateDB()
		},
	}
}

// runEngineUpdateDB refreshes the trivy DB and, when its volume exists on
// the host, the java DB inside the engine's advisory cache volumes. The
// engine container stays offline; cavet fetches, verifies, stages and swaps
// (engineclient.UpdateDB). The vuln DB must succeed (exit 2 otherwise); a
// failed java-db is reported and does not block the run.
func runEngineUpdateDB() error {
	s, err := openStore()
	if err != nil {
		return err
	}
	// Direct Load, not loadConfig: a malformed config must fail this command
	// rather than be silently overwritten by the pin write below.
	cfg, err := config.Load(s.Cavet + string(os.PathSeparator) + "config.yaml")
	if err != nil {
		return fail(err.Error())
	}
	root, _ := repoRoot()
	c := engineclient.New(engineRef(cfg), cfg.Engine.Digest, root, cfg.Engine.Variant)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := c.EnsureRunning(ctx); err != nil {
		return fail(err.Error())
	}

	considered, updated := 0, 0
	for _, a := range engineclient.Artifacts(cfg.Engine.Variant) {
		if a.Name == "java-db" {
			exists, err := c.VolumeExists(ctx, a.Volume)
			if err != nil {
				return fail(err.Error())
			}
			if !exists {
				fmt.Println("java-db: no volume on this host (core engine); nothing to update")
				continue
			}
		}
		considered++
		progress(fmt.Sprintf("%s: resolving", a.Name))
		digest, err := engineclient.ResolveDB(ctx, a)
		if err != nil {
			if a.Name == "vuln" {
				return fail(err.Error())
			}
			fmt.Printf("java-db: resolve failed: %v\n", err)
			continue
		}
		pin := cfg.Engine.DB.Digest
		if a.Name == "java-db" {
			pin = cfg.Engine.JavaDB.Digest
		}
		if digest == pin {
			fmt.Printf("%s: already current (%s)\n", a.Name, digest)
			continue
		}
		progress(fmt.Sprintf("%s: fetching", a.Name))
		sw, err := c.UpdateDB(ctx, a, digest)
		if err != nil {
			if a.Name == "vuln" {
				return fail(err.Error())
			}
			fmt.Printf("java-db: update failed: %v\n", err)
			continue
		}
		old := pin
		if old == "" {
			old = "(baked)"
		}
		fmt.Printf("%s: %s -> %s (advisories %s, %s)\n",
			a.Name, old, digest, sw.UpdatedAt.Format("2006-01-02"), humanSize(sw.Bytes))
		if err := recordDBUpdate(s, &cfg, a, sw); err != nil {
			return fail(err.Error())
		}
		updated++
	}
	fmt.Printf("update-db: %d of %d updated\n", updated, considered)
	return nil
}

// recordDBUpdate writes the swap record into state/db.json and the new
// digest into config.yaml, in that order, then appends the db_updated event
// (D3), all under the store lock (artefact §7.1): the rebaseline emission in
// cli/rebuild.go is the precedent for appending inside the lock window. Order
// is load-bearing: a failure between the two writes leaves the config pin
// stale, so the next run re-fetches (digest != pin) and rewrites both; pin
// first would short-circuit the next run and strand state/db.json in the
// baked era forever. Our file, no operator comments to preserve (init.go's
// recordDigest convention), but marshaled from the loaded config so
// pre-scaffold configs without the db keys migrate on first update instead
// of failing a placeholder match. Both writes are atomic (store/atomic.go):
// a torn config.yaml would fail the strict loader for every later command.
// The db_updated event is the log's answer to "when did the world change";
// state/db.json alone could not replay it after a rebuild.
func recordDBUpdate(s *store.Store, cfg *config.Config, a engineclient.Artifact, sw engineclient.Swap) error {
	rel, err := s.Lock()
	if err != nil {
		return err
	}
	defer rel()

	st, err := s.LoadDBState()
	if err != nil {
		return err
	}
	if st.Artifacts == nil {
		st.Artifacts = map[string]store.DBArtifact{}
	}
	prev := st.Artifacts[a.Name] // zero value on the first-ever swap (baked era)
	st.Artifacts[a.Name] = store.DBArtifact{
		Digest:    sw.Digest,
		UpdatedAt: sw.UpdatedAt,
		SwappedAt: sw.SwappedAt,
		Source:    "managed",
	}
	if err := s.WriteDBState(st); err != nil {
		return err
	}

	if a.Name == "java-db" {
		cfg.Engine.JavaDB.Digest = sw.Digest
	} else {
		cfg.Engine.DB.Digest = sw.Digest
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := store.AtomicWrite(filepath.Join(s.Cavet, "config.yaml"), b); err != nil {
		return err
	}

	d := events.DBUpdatedData{Artifact: a.Name, Digest: sw.Digest,
		UpdatedAt: sw.UpdatedAt.UTC().Format(time.RFC3339), Source: "managed"}
	// PreviousDigest stays empty on the baked era: no digest record exists to
	// name, and every consumer phrases that as "(baked)" at display time.
	if prev.Digest != "" {
		d.PreviousDigest = prev.Digest
	}
	ev, err := events.NewDBUpdated(time.Now().UTC(), events.ActorOperator, events.PhaseBuild,
		engineRef(*cfg), d)
	if err != nil {
		return err
	}
	return s.Append(ev)
}

// dbAge/humanSize moved: dbAge lives in version.go with the other advisory
// surface renderers; humanSize stays with the update-db output below.

// humanSize renders a compressed artifact size: MiB granularity covers the
// hundred-MB-to-GB advisory artifacts.
func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KiB", n>>10)
	}
}
