package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if err := regenerate(); err != nil {
		log.Fatalf("proto generation failed: %v", err)
	}
}

func regenerate() error {
	rootDir, err := os.Getwd()
	if err != nil {
		return err
	}

	modName, err := extractModule(filepath.Join(rootDir, "go.mod"))
	if err != nil {
		return err
	}

	src := filepath.Join(rootDir, "proto")
	dst := filepath.Join(rootDir, "internal", "grpc")

	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(dst, os.ModePerm); err != nil {
		return err
	}

	filesToGen, err := collectProtoFiles(src, modName)
	if err != nil {
		return err
	}

	return invokeProtoc(src, dst, filesToGen)
}

func extractModule(modFile string) (string, error) {
	f, err := os.Open(modFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
		}
	}
	return "", fmt.Errorf("module name not found")
}

func collectProtoFiles(baseDir, mod string) ([]string, error) {
	var result []string

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".proto") {
			result = append(result, path)
			if err := insertGoPackage(path, mod); err != nil {
				return fmt.Errorf("patching %s: %w", path, err)
			}
		}
		return nil
	})

	return result, err
}

func insertGoPackage(protoPath, mod string) error {
	raw, err := os.ReadFile(protoPath)
	if err != nil {
		return err
	}
	if bytes.Contains(raw, []byte("option go_package")) {
		return nil
	}

	absProto, err := filepath.Abs(protoPath)
	if err != nil {
		return err
	}

	root, err := locateModuleRoot(absProto)
	if err != nil {
		return err
	}

	rel, err := filepath.Rel(root, filepath.Dir(absProto))
	if err != nil {
		return err
	}

	goPath := filepath.ToSlash(filepath.Join(mod, rel))
	pkgName := filepath.Base(rel)

	var patched bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	injected := false
	for scanner.Scan() {
		line := scanner.Text()
		patched.WriteString(line + "\n")
		if !injected && strings.HasPrefix(line, "package ") {
			patched.WriteString(fmt.Sprintf("option go_package = \"%s;%s\";\n", goPath, pkgName))
			injected = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	return os.WriteFile(protoPath, patched.Bytes(), fs.ModePerm)
}

func locateModuleRoot(from string) (string, error) {
	dir := from
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return "", fmt.Errorf("project root not found")
}

func invokeProtoc(protoBase, output string, files []string) error {
	args := []string{
		"-I" + protoBase,
		"--go_out=" + output,
		"--go_opt=paths=source_relative",
		"--go-grpc_out=" + output,
		"--go-grpc_opt=paths=source_relative",
	}
	args = append(args, files...)

	cmd := exec.Command("protoc", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Println("protoc:", cmd.Args)
	return cmd.Run()
}
