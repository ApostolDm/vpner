package logging

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

var (
	currentLevel = LevelInfo
	levelMu      sync.RWMutex
	logger       = log.New(os.Stdout, "", log.LstdFlags)
)

func SetLevel(level string) {
	levelMu.Lock()
	defer levelMu.Unlock()

	switch strings.ToLower(level) {
	case "debug":
		currentLevel = LevelDebug
	case "info":
		currentLevel = LevelInfo
	case "warn", "warning":
		currentLevel = LevelWarn
	case "error":
		currentLevel = LevelError
	default:
		currentLevel = LevelInfo
	}
}

func logf(level Level, prefix, format string, args ...any) {
	levelMu.RLock()
	defer levelMu.RUnlock()

	if level > currentLevel {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if prefix != "" {
		msg = fmt.Sprintf("[%s] %s", strings.ToUpper(prefix), msg)
	}
	logger.Println(msg)
}

func Debugf(format string, args ...any) { logf(LevelDebug, "debug", format, args...) }
func Infof(format string, args ...any)  { logf(LevelInfo, "info", format, args...) }
func Warnf(format string, args ...any)  { logf(LevelWarn, "warn", format, args...) }
func Errorf(format string, args ...any) { logf(LevelError, "error", format, args...) }
