package kernel

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/mitchellh/go-homedir"
	"github.com/ti-mo/kconfig"
)

var (
	buildDir string
)

func init() {
	h, err := homedir.Expand("~/.cache/conntracct/kernels")
	if err != nil {
		panic(err)
	}
	buildDir = h
}

// Params is a map of kernel parameters.
type Params map[string]string

// Probe holds the name and kind of a kprobe/kretprobe.
type Probe struct {
	Kind string
	Name string
}

// ProgramName returns the Probe's program (function) name following the BCC
// convention: <kind>__<ksym_name>, eg. kprobe__nf_conntrack_free.
func (p Probe) ProgramName() string {
	return p.Kind + "__" + p.Name
}

// Probes is a list of kprobe/kretprobe entries present in the BPF program.
type Probes []Probe

// Kernel represents a kernel object.
type Kernel struct {
	Version string
	URL     string
	Params  Params
	Probes  Probes
}

// ArchiveName returns the file name of the archive based on its URL.
func (k Kernel) ArchiveName() string {
	return path.Base(k.URL)
}

// ArchivePath returns the path of the archive on disk.
func (k Kernel) ArchivePath() string {
	return path.Join(buildDir, k.ArchiveName())
}

// Name returns the name (plain version) of the kernel based on the name of the archive.
func (k Kernel) Name() string {
	return trimExt(k.ArchiveName())
}

// Directory returns the path on disk where the kernel is extracted.
func (k Kernel) Directory() string {
	return path.Join(buildDir, k.Name())
}

// Fetch ensures that a given kernel is downloaded and extracted to the temp directory.
func (k Kernel) Fetch() error {

	if mg.Verbose() {
		fmt.Println("Fetching ", k.Name(), "..")
	}

	if err := os.MkdirAll(buildDir, os.ModePerm); err != nil {
		return err
	}

	if err := curl(k.URL, k.ArchivePath()); err != nil {
		return err
	}

	if err := unarchive(k.ArchivePath(), buildDir, k.Directory()); err != nil {
		return err
	}

	if mg.Verbose() {
		fmt.Println("Successfully fetched", k.Name())
	}

	return nil
}

// Configure configures and prepares the kernel with the requested settings.
// If params is nil, the parameters defined on the Kernel will be used.
func (k Kernel) Configure(params Params) error {

	e := map[string]string{
		"ARCH": "x86",
		// "CROSS_COMPILE": "arm-linux-gnueabi-",
	}

	if mg.Verbose() {
		fmt.Println("Configuring", k.Name(), "..")
	}

	kcfile := path.Join(k.Directory(), ".config")

	// Initialize the default configuration to '.config'.
	// Include the 'clean' target to make sure all generated/prepared headers
	// from previous runs are erased.
	if err := runWithQuiet(e, "make", "-C", k.Directory(), "clean", "defconfig"); err != nil {
		return err
	}

	kc := kconfig.New()
	if err := kc.Read(kcfile); err != nil {
		return err
	}

	if params != nil {
		kc.Merge(params)
	} else {
		kc.Merge(k.Params)
	}

	if err := kc.Write(kcfile); err != nil {
		return err
	}

	// Prepare kernel headers.
	if err := runWithQuiet(e, "make", "-C", k.Directory(), "olddefconfig", "prepare"); err != nil {
		return err
	}

	if mg.Verbose() {
		fmt.Println("Successfully configured", k.Name())
	}

	return nil
}

// runWithQuiet calls sh.RunWith, but buffers stderr and only displays it when
// the command failed.
func runWithQuiet(env map[string]string, cmd string, args ...string) error {
	var output io.Writer
	if mg.Verbose() {
		output = os.Stdout
	}
	errBuf := &bytes.Buffer{}
	_, err := sh.Exec(env, output, errBuf, cmd, args...)

	if err != nil {
		fmt.Println(strings.TrimSuffix(errBuf.String(), "\n"))
	}

	return err
}
