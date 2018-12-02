package kallsyms_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gitlab.com/0ptr/conntracct/pkg/kallsyms"
)

func TestKallsyms(t *testing.T) {

	var syms []string
	var err error
	findSym := "run_init_process"

	_, err = kallsyms.Get()
	assert.EqualError(t, err, "no ksyms currently stored in package, call kallsyms.Refresh() first", "get before refresh")

	_, err = kallsyms.Find(findSym)
	assert.EqualError(t, err, "no ksyms currently stored in package, call kallsyms.Refresh() first", "find before refresh")

	err = kallsyms.Refresh()
	assert.NoError(t, err, "refresh")

	syms, err = kallsyms.Get()
	assert.NoError(t, err, "get error")
	assert.NotEmpty(t, syms, "get syms")

	fs, err := kallsyms.Find(findSym)
	assert.NoError(t, err, "find symbol error")
	assert.True(t, fs, "find symbol result")
}
