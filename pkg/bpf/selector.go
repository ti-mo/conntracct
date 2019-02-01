package bpf

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"

	"github.com/blang/semver"
	"github.com/rakyll/statik/fs"
	"github.com/ti-mo/conntracct/pkg/kernel"
)

// Select returns a bytes.Reader holding the BPF program to be used for
// the given kernel release kr. Returns the bytes.Reader of the selected probe
// and the kernel.Kernel it was built against.
func Select(kr string) (*bytes.Reader, kernel.Kernel, error) {

	bfs, err := fs.New()
	if err != nil {
		return nil, kernel.Kernel{}, err
	}

	// Find an acceptable probe version for the running kernel version.
	// Always returns a result. If there is no match, will return the lowest probe version.
	probe, err := findProbe(kr, kernel.Builds)
	if err != nil {
		return nil, kernel.Kernel{}, err
	}

	bpfFile := fmt.Sprintf("/acct/%s.o", probe.Version)
	b, err := fs.ReadFile(bfs, bpfFile)
	if err != nil {
		return nil, kernel.Kernel{}, errors.Wrap(err, bpfFile)
	}
	br := bytes.NewReader(b)

	return br, probe, nil
}

// findProbe returns a compatible BPF probe version in a list of kernels
// based on the given kernel version string k.
func findProbe(k string, kernels map[string]kernel.Kernel) (kernel.Kernel, error) {

	// Parse the running kernel version.
	kv, err := semver.Make(k)
	if err != nil {
		return kernel.Kernel{}, err
	}

	// Gather versions of all probes and sort them in ascending order.
	versions := make([]semver.Version, 0)
	for v := range kernels {
		versions = append(versions, semver.MustParse(v))
	}
	semver.Sort(versions)

	// Look for a version that is smaller than the running kernel version.
	rs := fmt.Sprintf("<= %s", k)
	kr := semver.MustParseRange(rs)
	if v, err := findRange(versions, kr); err == nil {
		return kernels[v], nil
	}

	// Look for the highest patch release matching the running kernel's major/minor version.
	rs = fmt.Sprintf("%d.%d.x", kv.Major, kv.Minor)
	kr = semver.MustParseRange(rs)
	if v, err := findRange(versions, kr); err == nil {
		return kernels[v], nil
	}

	// Return the lowest version if none match.
	return kernels[versions[0].String()], nil
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
