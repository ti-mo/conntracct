package kernel

var (
	buildDir = "/tmp/conntracct/kernels"
)

// SetBuildDir set the package-wide build directory.
func SetBuildDir(p string) {
	buildDir = p
}

// GetBuildDir gets the package-wide build directory.
func GetBuildDir() string {
	return buildDir
}
