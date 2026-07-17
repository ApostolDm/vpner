package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

const DefaultRepo = "ApostolDm/vpner"

type Release struct {
	TagName    string  `json:"tag_name"`
	Name       string  `json:"name"`
	Prerelease bool    `json:"prerelease"`
	Draft      bool    `json:"draft"`
	HTMLURL    string  `json:"html_url"`
	Assets     []Asset `json:"assets"`
}

type Asset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
	Size        int64  `json:"size"`
	Digest      string `json:"digest"`
}

func FetchReleases(ctx context.Context, client *http.Client, repo string) ([]Release, error) {
	if repo == "" {
		repo = DefaultRepo
	}
	url := "https://api.github.com/repos/" + repo + "/releases?per_page=100"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vpner-updater")
	req.Header.Set("Accept", "application/vnd.github+json")
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("github API %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var releases []Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("decode releases: %w", err)
	}
	return releases, nil
}

func PickLatest(releases []Release, includePrerelease bool) (Release, bool) {
	var best Release
	found := false
	for _, r := range releases {
		if r.Draft {
			continue
		}
		if r.Prerelease && !includePrerelease {
			continue
		}
		if !found || CompareVersions(r.TagName, best.TagName) > 0 {
			best = r
			found = true
		}
	}
	return best, found
}

func (r Release) SelectIPK(pkgName string, archTags []string, preferKN bool) (Asset, bool) {
	for _, arch := range archTags {
		plainSuffix := "_" + arch + ".ipk"
		knSuffix := "_" + arch + "_kn.ipk"
		var plain, kn *Asset
		for i := range r.Assets {
			name := r.Assets[i].Name
			if !strings.HasPrefix(name, pkgName+"_") {
				continue
			}
			switch {
			case strings.HasSuffix(name, knSuffix):
				kn = &r.Assets[i]
			case strings.HasSuffix(name, plainSuffix):
				plain = &r.Assets[i]
			}
		}
		order := []*Asset{plain, kn}
		if preferKN {
			order = []*Asset{kn, plain}
		}
		for _, a := range order {
			if a != nil {
				return *a, true
			}
		}
	}
	return Asset{}, false
}

func (r Release) FindAsset(name string) (Asset, bool) {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return r.Assets[i], true
		}
	}
	return Asset{}, false
}

func CompareVersions(a, b string) int {
	na, prea, oka := parseVersion(a)
	nb, preb, okb := parseVersion(b)

	switch {
	case !oka && !okb:
		return strings.Compare(a, b)
	case !oka:
		return -1
	case !okb:
		return 1
	}

	for i := 0; i < len(na) || i < len(nb); i++ {
		var x, y int
		if i < len(na) {
			x = na[i]
		}
		if i < len(nb) {
			y = nb[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}

	switch {
	case prea == "" && preb == "":
		return 0
	case prea == "":
		return 1
	case preb == "":
		return -1
	default:
		return strings.Compare(strings.ToLower(prea), strings.ToLower(preb))
	}
}

func parseVersion(v string) (nums []int, pre string, ok bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if v == "" {
		return nil, "", false
	}
	core := v
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		core = v[:idx]
		pre = strings.TrimLeft(v[idx:], "-+")
	}
	for _, part := range strings.Split(core, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, "", false
		}
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		return nil, "", false
	}
	return nums, pre, true
}

func sortArchByPriority(pairs []ArchPriority) []string {
	sort.SliceStable(pairs, func(i, j int) bool {
		return pairs[i].Priority > pairs[j].Priority
	})
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.Name)
	}
	return out
}

type ArchPriority struct {
	Name     string
	Priority int
}

func ParseOpkgArchitectures(output string) []string {
	var pairs []ArchPriority
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "arch" {
			continue
		}
		name := fields[1]
		if name == "all" || name == "noarch" {
			continue
		}
		prio, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		pairs = append(pairs, ArchPriority{Name: name, Priority: prio})
	}
	return sortArchByPriority(pairs)
}
