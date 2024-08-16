package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

func createDirsIfNotExist(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("can't create directories: %w", err)
		}
	}
	return nil
}

func EnsureFileExists(filePath string) error {
	dir := filepath.Dir(filePath)

	if err := createDirsIfNotExist(dir); err != nil {
		LogErrorF("EnsureFileExists error - unable to create directory for %s: %v", filePath, err)
		return err
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		file, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0644)
		if err != nil {
			LogErrorF("EnsureFileExists error - can't create file %s: %v", filePath, err)
			return fmt.Errorf("can't create file: %w", err)
		}
		defer file.Close()
		LogF("File created: %s", filePath)
	}

	return nil
}

func EnsureDirExists(dirName string) error {
	if err := createDirsIfNotExist(dirName); err != nil {
		LogErrorF("EnsureDirExists error - can't create directory %s: %v", dirName, err)
		return err
	}
	return nil
}

func EnsureExecutable(filePath string) error {
	if _, err := os.Stat(filePath); err != nil {
		return fmt.Errorf("file %s is not created: %w", filePath, err)
	}

	if err := os.Chmod(filePath, 0755); err != nil {
		LogErrorF("EnsureExecutable error - failed to set executable permission for %s: %v", filePath, err)
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	LogF("Permissions updated to executable: %s", filePath)
	return nil
}
