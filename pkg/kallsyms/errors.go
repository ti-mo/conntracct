package kallsyms

import "errors"

var (
	errNoKsyms = errors.New("no ksyms currently stored in package, call kallsyms.Refresh() first")
)
