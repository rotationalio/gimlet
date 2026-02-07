package gimlet

import (
	"fmt"

	"go.rtnl.ai/x/semver"
)

// Version component constants for the current library.
// This version information is primarily used for OpenTelemetry semantic conventions.
// But can be used by other middleware to identify the version of the library and
// ensure compatibility with third party libraries.
const (
	VersionMajor         = 1
	VersionMinor         = 5
	VersionPatch         = 0
	VersionReleaseLevel  = "final"
	VersionReleaseNumber = 11
)

// Version returns the semantic version for the current build.
func Version() string {
	vers := semver.Version{
		Major:      VersionMajor,
		Minor:      VersionMinor,
		Patch:      VersionPatch,
		PreRelease: PreRelease(),
	}

	return vers.Short()
}

func PreRelease() string {
	if VersionReleaseLevel != "" && VersionReleaseLevel != "final" {
		if VersionReleaseNumber > 0 {
			return fmt.Sprintf("%s.%d", VersionReleaseLevel, VersionReleaseNumber)
		}
		return VersionReleaseLevel
	}
	return ""
}
