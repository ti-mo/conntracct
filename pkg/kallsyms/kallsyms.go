package kallsyms

import (
	"io/ioutil"
	"strings"
)

var ksyms []string

// Refresh updates the package-internal list of kernel symbols with the
// ones parsed from /proc/kallsyms. Expensive operation, call sparingly.
func Refresh() error {

	f, err := ioutil.ReadFile("/proc/kallsyms")
	if err != nil {
		return err
	}

	// Trim trailing newlines and split by newline
	content := strings.Split(strings.TrimSuffix(string(f), "\n"), "\n")
	out := make([]string, len(content))

	for i, l := range content {

		// Replace any tabs by spaces
		l = strings.Replace(l, "\t", " ", -1)

		// Get the third column
		out[i] = strings.Split(l, " ")[2]
	}

	ksyms = out

	return nil
}

// Get returns all kernel symbols currently stored in the package. Call Refresh()
// first to update the internal list. Will return error when the list is empty.
func Get() ([]string, error) {

	if len(ksyms) == 0 {
		return nil, errNoKsyms
	}

	return ksyms, nil
}

// Find looks for a given string in the package's list of kernel symbols.
// Call Refresh() first to update the internal list. Will return error when
// the internal list is empty.
func Find(sym string) (bool, error) {

	if len(ksyms) == 0 {
		return false, errNoKsyms
	}

	for _, v := range ksyms {
		if v == sym {
			return true, nil
		}
	}

	return false, nil
}
