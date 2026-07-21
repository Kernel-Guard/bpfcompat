package freshness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Entry is one kernel release from a kernel-crawler list.json. Headers
// carries the distro pool URLs for the header packages; for Ubuntu the
// kernel image/modules .debs live in the same pool directory, which is what
// makes dense kernel sweeps possible for releases apt no longer indexes.
type Entry struct {
	KernelRelease string   `json:"kernelrelease"`
	Target        string   `json:"target"`
	Headers       []string `json:"headers"`
}

// Inventory maps a kernel-crawler distro key (ubuntu, rocky, amazonlinux2023,
// ...) to its kernel entries for one architecture.
type Inventory map[string][]Entry

// Newest returns the highest kernel release matching ref, or "" when nothing
// matches.
func (inv Inventory) Newest(ref CrawlerRef) string {
	best := ""
	for _, e := range inv[ref.Distro] {
		if ref.Target != "" && e.Target != ref.Target {
			continue
		}
		if !strings.HasPrefix(e.KernelRelease, ref.ReleasePrefix) {
			continue
		}
		if ref.ReleaseContains != "" && !strings.Contains(e.KernelRelease, ref.ReleaseContains) {
			continue
		}
		if best == "" || CompareKernelReleases(e.KernelRelease, best) > 0 {
			best = e.KernelRelease
		}
	}
	return best
}

// SweepEntries returns the count most recent distinct kernel releases
// matching ref, newest first, with their package URLs. Used to generate
// dense kernel-sweep matrices.
func (inv Inventory) SweepEntries(ref CrawlerRef, count int) []Entry {
	seen := map[string]bool{}
	matches := []Entry{}
	for _, e := range inv[ref.Distro] {
		if ref.Target != "" && e.Target != ref.Target {
			continue
		}
		if !strings.HasPrefix(e.KernelRelease, ref.ReleasePrefix) {
			continue
		}
		if ref.ReleaseContains != "" && !strings.Contains(e.KernelRelease, ref.ReleaseContains) {
			continue
		}
		if seen[e.KernelRelease] {
			continue
		}
		seen[e.KernelRelease] = true
		matches = append(matches, e)
	}
	sort.Slice(matches, func(i, j int) bool {
		return CompareKernelReleases(matches[i].KernelRelease, matches[j].KernelRelease) > 0
	})
	if count > 0 && len(matches) > count {
		matches = matches[:count]
	}
	return matches
}

// UbuntuKernelDebs derives the kernel image and modules .deb URLs for an
// Ubuntu release from its crawler entry. apt only indexes the current ABI
// per pocket — superseded kernels stay downloadable in the pool but are
// invisible to `apt-get install` — so dense sweeps must install the .debs
// directly. The flavor-specific headers URL
// (.../linux-headers-<release>_<version>_<arch>.deb) pins the pool
// directory, exact package version, and architecture; the modules and
// unsigned image packages sit alongside it.
func UbuntuKernelDebs(entry Entry) ([]string, error) {
	release := entry.KernelRelease
	for _, headerURL := range entry.Headers {
		base := headerURL[strings.LastIndex(headerURL, "/")+1:]
		prefix := "linux-headers-" + release + "_"
		if !strings.HasPrefix(base, prefix) || !strings.HasSuffix(base, ".deb") {
			continue
		}
		rest := strings.TrimSuffix(strings.TrimPrefix(base, prefix), ".deb")
		versionArch := strings.SplitN(rest, "_", 2)
		if len(versionArch) != 2 || versionArch[1] == "all" {
			continue
		}
		dir := headerURL[:strings.LastIndex(headerURL, "/")+1]
		version, arch := versionArch[0], versionArch[1]
		return []string{
			httpsURL(fmt.Sprintf("%slinux-modules-%s_%s_%s.deb", dir, release, version, arch)),
			httpsURL(fmt.Sprintf("%slinux-image-unsigned-%s_%s_%s.deb", dir, release, version, arch)),
		}, nil
	}
	return nil, fmt.Errorf("no flavor-specific headers URL for %s to derive package URLs from", release)
}

// httpsURL upgrades a package URL to https. kernel-crawler publishes plain
// http mirror URLs, but every mirror we derive from serves the same paths
// over TLS, and these packages are installed as a kernel inside the guest —
// so the download must not be modifiable in transit. Distro package
// signatures are still verified at install time; this is defence in depth,
// not a replacement for them.
func httpsURL(raw string) string {
	if strings.HasPrefix(raw, "http://") {
		return "https://" + strings.TrimPrefix(raw, "http://")
	}
	return raw
}

// RHELKernelRPMs derives the bootable kernel RPM URLs for a RHEL-family
// release from its crawler entry. The crawler publishes only the
// kernel-devel RPM, which lives in AppStream; the packages that actually
// provide a bootable kernel (vmlinuz plus modules) sit in BaseOS under the
// same repository layout, so the AppStream URL pins the mirror, repository
// version and architecture, and swapping the component and package name
// yields the rest. The per-letter subdirectory some mirrors use (Rocky's
// Packages/k/) is preserved because only the file name is replaced.
func RHELKernelRPMs(entry Entry) ([]string, error) {
	release := entry.KernelRelease
	for _, headerURL := range entry.Headers {
		slash := strings.LastIndex(headerURL, "/")
		if slash < 0 {
			continue
		}
		base := headerURL[slash+1:]
		want := "kernel-devel-" + release + ".rpm"
		if base != want {
			continue
		}
		dir := headerURL[:slash+1]
		if !strings.Contains(dir, "/AppStream/") {
			return nil, fmt.Errorf("headers URL for %s is not under AppStream: %s", release, headerURL)
		}
		dir = strings.Replace(dir, "/AppStream/", "/BaseOS/", 1)
		// kernel-core carries vmlinuz; the modules packages carry the
		// drivers a guest needs to boot. Any remaining dependency is
		// resolved by dnf from the guest's enabled repositories.
		return []string{
			httpsURL(dir + "kernel-core-" + release + ".rpm"),
			httpsURL(dir + "kernel-modules-core-" + release + ".rpm"),
			httpsURL(dir + "kernel-modules-" + release + ".rpm"),
		}, nil
	}
	return nil, fmt.Errorf("no kernel-devel headers URL for %s to derive package URLs from", release)
}

// ParseInventory decodes a kernel-crawler list.json stream.
func ParseInventory(r io.Reader) (Inventory, error) {
	var inv Inventory
	if err := json.NewDecoder(r).Decode(&inv); err != nil {
		return nil, fmt.Errorf("decode crawler inventory: %w", err)
	}
	return inv, nil
}

// DefaultCrawlerBase is where falcosecurity/kernel-crawler publishes its
// weekly per-arch inventories as <base>/<arch>/list.json.
const DefaultCrawlerBase = "https://falcosecurity.github.io/kernel-crawler"

// FetchInventory downloads and parses <base>/<arch>/list.json. base must be
// an https URL; use LoadInventoryFile for local copies.
func FetchInventory(ctx context.Context, base, arch string, timeout time.Duration) (Inventory, error) {
	listURL := strings.TrimSuffix(base, "/") + "/" + arch + "/list.json"
	parsed, err := url.Parse(listURL)
	if err != nil {
		return nil, fmt.Errorf("crawler URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("crawler URL must be https, got %q", parsed.Scheme)
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, parsed.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("crawler request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", parsed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", parsed, resp.StatusCode)
	}
	return ParseInventory(resp.Body)
}

// LoadInventoryFile parses a local copy of a kernel-crawler list.json.
func LoadInventoryFile(path string) (Inventory, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path by design
	if err != nil {
		return nil, fmt.Errorf("open crawler inventory: %w", err)
	}
	defer f.Close()
	return ParseInventory(f)
}
