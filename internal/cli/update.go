package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ApostolDmitry/vpner/internal/buildinfo"
	"github.com/ApostolDmitry/vpner/internal/selfupdate"
)

const (
	updateInitScript = "/opt/etc/init.d/S95vpnerd"
	updatePkgName    = "vpnerd"
	updateStateDir   = "/opt/etc/vpner"
)

func updateCmd() *cobra.Command {
	var (
		apply      bool
		prerelease bool
		kn         bool
		withCLI    bool
		force      bool
		noBackup   bool
		repo       string
	)

	cmd := &cobra.Command{
		Use:               "update",
		Short:             "Check for and install vpner updates from GitHub releases",
		PersistentPreRunE: noDial,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			client := &http.Client{Timeout: 60 * time.Second}
			releases, err := selfupdate.FetchReleases(ctx, client, repo)
			if err != nil {
				return err
			}
			latest, ok := selfupdate.PickLatest(releases, prerelease)
			if !ok {
				return fmt.Errorf("no releases found for %s", firstNonEmpty(repo, selfupdate.DefaultRepo))
			}

			current := buildinfo.Version
			fmt.Printf("Current: %s\n", current)
			fmt.Printf("Latest:  %s", latest.TagName)
			if latest.Prerelease {
				fmt.Print(" (pre-release)")
			}
			fmt.Println()
			if latest.HTMLURL != "" {
				fmt.Printf("Release: %s\n", latest.HTMLURL)
			}

			if selfupdate.CompareVersions(current, latest.TagName) >= 0 && !force {
				fmt.Println("Already up to date.")
				return nil
			}

			fmt.Printf("Update available: %s -> %s\n", current, latest.TagName)
			if !apply {
				fmt.Println("Run 'vpnerctl update --apply' to download and install it.")
				return nil
			}
			return applyUpdate(ctx, client, latest, kn, withCLI, force, !noBackup)
		},
	}

	cmd.Flags().BoolVar(&apply, "apply", false, "download and install the update")
	cmd.Flags().BoolVar(&prerelease, "prerelease", false, "include pre-releases when picking the latest version")
	cmd.Flags().BoolVar(&kn, "kn", false, "prefer the Keenetic (_kn) package variant")
	cmd.Flags().BoolVar(&withCLI, "cli", false, "also replace the vpnerctl binary (large download)")
	cmd.Flags().BoolVar(&force, "force", false, "install even if already up to date")
	cmd.Flags().BoolVar(&noBackup, "no-backup", false, "skip backing up config files before installing")
	cmd.Flags().StringVar(&repo, "repo", selfupdate.DefaultRepo, "GitHub owner/repo to check")
	return cmd
}

func applyUpdate(ctx context.Context, client *http.Client, rel selfupdate.Release, preferKN, withCLI, force, doBackup bool) error {
	archTags := detectArchTags()
	if len(archTags) == 0 {
		return fmt.Errorf("could not detect the opkg architecture; run this on the router (needs opkg)")
	}

	asset, ok := rel.SelectIPK(updatePkgName, archTags, preferKN)
	if !ok {
		return fmt.Errorf("no %s .ipk for architecture %v in release %s", updatePkgName, archTags, rel.TagName)
	}

	if doBackup {
		dest, err := backupConfigs(updateStateDir)
		if err != nil {
			return fmt.Errorf("config backup failed (use --no-backup to skip): %w", err)
		}
		if dest == "" {
			fmt.Println("No config files to back up.")
		} else {
			fmt.Printf("Backed up configs to %s\n", dest)
		}
	}

	ipkPath := filepath.Join(os.TempDir(), asset.Name)
	fmt.Printf("Downloading %s (%s)...\n", asset.Name, humanSize(asset.Size))
	if err := downloadVerify(ctx, client, asset, ipkPath); err != nil {
		return err
	}
	defer os.Remove(ipkPath)

	fmt.Println("Installing package via opkg...")
	opkgArgs := []string{"install"}
	if force {
		opkgArgs = append(opkgArgs, "--force-reinstall")
	}
	opkgArgs = append(opkgArgs, ipkPath)
	if out, err := exec.CommandContext(ctx, "opkg", opkgArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("opkg install failed: %v\n%s", err, strings.TrimSpace(string(out)))
	}

	if withCLI {
		if err := updateCLIBinary(ctx, client, rel); err != nil {
			fmt.Printf("WARNING: vpnerctl self-update skipped: %v\n", err)
		}
	}

	restartService(ctx)
	fmt.Printf("Updated to %s. Verify with 'vpnerctl status'.\n", rel.TagName)
	return nil
}

func updateCLIBinary(ctx context.Context, client *http.Client, rel selfupdate.Release) error {
	name := "vpnerctl-linux-" + runtime.GOARCH
	asset, ok := rel.FindAsset(name)
	if !ok {
		return fmt.Errorf("release has no %s", name)
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current binary: %w", err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return fmt.Errorf("resolve current binary: %w", err)
	}
	tmp := self + ".new"
	fmt.Printf("Downloading %s (%s)...\n", asset.Name, humanSize(asset.Size))
	if err := downloadVerify(ctx, client, asset, tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, self); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", self, err)
	}
	fmt.Printf("Replaced %s\n", self)
	return nil
}

func backupConfigs(stateDir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(stateDir, "*.yaml"))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", nil
	}
	dest := filepath.Join(stateDir, "backup-"+time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(dest, 0755); err != nil {
		return "", err
	}
	for _, src := range matches {
		if err := copyFile(src, filepath.Join(dest, filepath.Base(src))); err != nil {
			return "", err
		}
	}
	return dest, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func detectArchTags() []string {
	out, err := exec.Command("opkg", "print-architecture").Output()
	if err != nil {
		return nil
	}
	return selfupdate.ParseOpkgArchitectures(string(out))
}

func downloadVerify(ctx context.Context, client *http.Client, asset selfupdate.Asset, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.DownloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "vpner-updater")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", asset.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %s", asset.Name, resp.Status)
	}

	tmp := dest + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	if want, ok := strings.CutPrefix(asset.Digest, "sha256:"); ok && want != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(want, got) {
			os.Remove(tmp)
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", asset.Name, want, got)
		}
	}

	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func restartService(ctx context.Context) {
	if _, err := os.Stat(updateInitScript); err != nil {
		fmt.Printf("Start the service manually: %s start\n", updateInitScript)
		return
	}
	fmt.Println("Restarting vpnerd...")
	if out, err := exec.CommandContext(ctx, updateInitScript, "restart").CombinedOutput(); err != nil {
		fmt.Printf("WARNING: restart failed: %v\n%s\nStart it manually: %s start\n",
			err, strings.TrimSpace(string(out)), updateInitScript)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
