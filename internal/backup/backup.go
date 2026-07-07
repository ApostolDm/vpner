package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Create(stateDir, outFile string) error {
	stateDir = filepath.Clean(stateDir)
	info, err := os.Stat(stateDir)
	if err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("state path %s is not a directory", stateDir)
	}

	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	absOut, _ := filepath.Abs(outFile)
	return filepath.Walk(stateDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if abs, _ := filepath.Abs(path); abs == absOut {
			return nil
		}
		rel, err := filepath.Rel(stateDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			return nil
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if fi.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(tw, src)
		return err
	})
}

func Restore(inFile, stateDir string) error {
	f, err := os.Open(inFile)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	stateDir = filepath.Clean(stateDir)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	prefix := stateDir + string(os.PathSeparator)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if name == "." || filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
			return fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		target := filepath.Join(stateDir, name)
		if target != stateDir && !strings.HasPrefix(target, prefix) {
			return fmt.Errorf("path escapes state dir: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)&0o777); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}
