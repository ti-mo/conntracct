package bpf

import (
	"bytes"
	"fmt"

	"github.com/blang/semver"
	"github.com/rakyll/statik/fs"
	"gitlab.com/0ptr/conntracct/pkg/kernel"
)

// Select returns a bytes.Reader holding the BPF program to be used for
// the given kernel release kr. Returns the reader and the version of
// the selected probe.
func Select(kr string) (*bytes.Reader, string, error) {

	bfs, err := fs.New()
	if err != nil {
		return nil, "", err
	}

	probe, err := findProbe(kr, kernel.Builds)
	if err != nil {
		return nil, "", err
	}

	b, err := fs.ReadFile(bfs, fmt.Sprintf("/acct/%s.o", probe))
	if err != nil {
		return nil, "", err
	}
	br := bytes.NewReader(b)

	return br, probe, nil
}

// findProbe finds a compatible BPF probe version in a list of kernels
// based on the given kernel version string k.
func findProbe(k string, kernels []kernel.Kernel) (string, error) {

	// Parse the running kernel version.
	kv, err := semver.Make(k)
	if err != nil {
		return "", err
	}

	// Gather versions of all probes and sort them in ascending order.
	versions := make([]semver.Version, len(kernels))
	for i, kb := range kernels {
		versions[i] = semver.MustParse(kb.Version)
	}
	semver.Sort(versions)

	// Look for a version that is smaller than the running kernel version.
	rs := fmt.Sprintf("<= %s", k)
	kr := semver.MustParseRange(rs)
	if v, err := findRange(versions, kr); err == nil {
		return v, nil
	}

	// Look for the highest patch release matching the running kernel's major/minor version.
	rs = fmt.Sprintf("%d.%d.x", kv.Major, kv.Minor)
	kr = semver.MustParseRange(rs)
	if v, err := findRange(versions, kr); err == nil {
		return v, nil
	}

	// Return the lowest version if none match.
	return versions[0].String(), nil
}

// findRange loops over a sorted list of semver.Versions v and returns
// the highest version matching the given semver.Range.
func findRange(v semver.Versions, r semver.Range) (string, error) {

	for i := len(v) - 1; i >= 0; i-- {
		vi := v[i]
		if r(vi) {
			return vi.String(), nil
		}
	}

	return "", errNotInRange
}
