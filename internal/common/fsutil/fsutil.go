package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

func EnsureFile(path string) error {
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		file, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("create file %s: %w", path, err)
		}
		_ = file.Close()
	}
	return nil
}

func EnsureDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("create dir %s: %w", path, err)
		}
	}
	return nil
}

func EnsureExecutable(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("file %s is not created: %w", path, err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
