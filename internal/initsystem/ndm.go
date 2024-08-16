package initsystem

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ApostolDmitry/vpner/internal/utils"
)

const baseDir = "/opt/etc/ndm"

var commandDirs = map[string]string{
	"fs":             "fs.d",
	"ifcreated":      "ifcreated.d",
	"ifdestroyed":    "ifdestroyed.d",
	"iflayerchanged": "iflayerchanged.d",
	"ifstatechanged": "ifstatechanged.d",
	"netfilter":      "netfilter.d",
	"wan":            "wan.d",
}

func getExecutablePath() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	return execPath, nil
}

func generateHookScript(vpnerPath, command string) []byte {
	return []byte(fmt.Sprintf(`#!/bin/sh
%s system hook %s "$@"`, vpnerPath, command))
}

func ensureScript(command, dirPath, vpnerPath string) error {
	scriptPath := filepath.Join(dirPath, "vpner-hook-"+command+".sh")
	expectedContent := generateHookScript(vpnerPath, command)

	if err := utils.EnsureFileExists(scriptPath); err != nil {
		return fmt.Errorf("failed to create hook script file %s: %w", scriptPath, err)
	}

	currentContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read hook script file %s: %w", scriptPath, err)
	}

	if !bytes.Equal(bytes.TrimSpace(currentContent), bytes.TrimSpace(expectedContent)) {
		if err := os.WriteFile(scriptPath, expectedContent, 0755); err != nil {
			return fmt.Errorf("failed to overwrite hook script file %s: %w", scriptPath, err)
		}
		utils.LogF("Hook script updated: %s", scriptPath)
	}

	if err := utils.EnsureExecutable(scriptPath); err != nil {
		return fmt.Errorf("failed to set executable permission for %s: %w", scriptPath, err)
	}

	return nil
}

func InitNdmHooks() {
	utils.LogF("Initializing NDM hook scripts...")

	vpnerPath, err := getExecutablePath()
	if err != nil {
		utils.LogErrorF("InitNdmHooks error: %v", err)
		return
	}

	for command, dir := range commandDirs {
		dirPath := filepath.Join(baseDir, dir)

		if err := utils.EnsureDirExists(dirPath); err != nil {
			utils.LogErrorF("Failed to create directory %s: %v", dirPath, err)
			continue
		}

		if err := ensureScript(command, dirPath, vpnerPath); err != nil {
			utils.LogErrorF("Failed to create hook for '%s': %v", command, err)
		}
	}

	utils.LogF("NDM hook scripts initialization completed.")
}
