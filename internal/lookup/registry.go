package lookup

import (
	"context"
	"fmt"
	"strings"
)

// Registry — package existence, deprecation, and maintenance across the four
// default ecosystems, dispatched on the purl type (cli-spec §11). No auth.

type Registry struct {
	NpmBase   string
	PyPIBase  string
	CratesBase string
	GoBase    string
}

func NewRegistry() *Registry {
	return &Registry{
		NpmBase:    "https://registry.npmjs.org",
		PyPIBase:   "https://pypi.org/pypi",
		CratesBase: "https://crates.io/api/v1/crates",
		GoBase:     "https://proxy.golang.org",
	}
}

// PackageInfo is the common projection of one package coordinate.
type PackageInfo struct {
	Exists     bool
	Deprecated bool
	Version    string
	URL        string
}

// purl parses "pkg:npm/lodash@4.17.20" into (type, path-without-version,
// version). Loose on purpose: the shape check happened at the CLI boundary.
func purl(ref string) (typ, name, version string) {
	s := strings.TrimPrefix(ref, "pkg:")
	if i := strings.Index(s, "/"); i > 0 {
		typ = s[:i]
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		version = s[i+1:]
		s = s[:i]
	}
	return typ, s, version
}

func (r *Registry) Lookup(ctx context.Context, ref string) (*PackageInfo, error) {
	typ, name, version := purl(ref)
	switch typ {
	case "npm":
		return r.npm(ctx, name, version)
	case "pypi":
		return r.pypi(ctx, name, version)
	case "cargo", "crates":
		return r.crates(ctx, name)
	case "golang", "go":
		return r.goMod(ctx, name)
	}
	return nil, &ErrDegraded{Source: "registry", Err: fmt.Errorf("unsupported ecosystem %q", typ)}
}

func (r *Registry) npm(ctx context.Context, name, version string) (*PackageInfo, error) {
	if version == "" {
		return nil, &ErrDegraded{Source: "registry", Err: fmt.Errorf("purl needs a version")}
	}
	var doc struct {
		Deprecated string `json:"deprecated"` // present only on deprecated versions
	}
	if err := getJSON(ctx, r.NpmBase+"/"+name+"/"+version, nil, &doc); err != nil {
		return nil, err
	}
	return &PackageInfo{
		Exists: true, Deprecated: doc.Deprecated != "", Version: version,
		URL: "https://www.npmjs.com/package/" + name + "/v/" + version,
	}, nil
}

func (r *Registry) pypi(ctx context.Context, name, version string) (*PackageInfo, error) {
	path := name
	if version != "" {
		path = name + "/" + version
	}
	var doc struct {
		Info struct {
			Version     string `json:"version"`
			Yanked      bool   `json:"yanked"`
		} `json:"info"`
	}
	if err := getJSON(ctx, r.PyPIBase+"/"+path+"/json", nil, &doc); err != nil {
		return nil, err
	}
	return &PackageInfo{
		Exists: true, Version: doc.Info.Version,
		URL: "https://pypi.org/project/" + name + "/",
	}, nil
}

func (r *Registry) crates(ctx context.Context, name string) (*PackageInfo, error) {
	var doc struct {
		Crate struct {
			Name       string `json:"name"`
			MaxVersion string `json:"max_stable_version"`
		} `json:"crate"`
	}
	if err := getJSON(ctx, r.CratesBase+"/"+name, nil, &doc); err != nil {
		return nil, err
	}
	return &PackageInfo{
		Exists: true, Version: doc.Crate.MaxVersion,
		URL: "https://crates.io/crates/" + name,
	}, nil
}

func (r *Registry) goMod(ctx context.Context, name string) (*PackageInfo, error) {
	var latest struct {
		Version string `json:"Version"`
	}
	if err := getJSON(ctx, r.GoBase+"/"+name+"/@latest", nil, &latest); err != nil {
		return nil, err
	}
	return &PackageInfo{
		Exists: true, Version: latest.Version,
		URL: "https://pkg.go.dev/" + name,
	}, nil
}
