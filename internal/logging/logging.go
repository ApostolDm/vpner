package logging

import (
	"fmt"
	"io"
	"log"
	"log/syslog"
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
	sinkMu       sync.RWMutex
	sink         logSink = newFallbackSink()
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

func Configure() error {
	writer, err := newSyslogSink()
	sinkMu.Lock()
	defer sinkMu.Unlock()
	if err != nil {
		sink = newFallbackSink()
		return err
	}
	sink = writer
	return nil
}

func logf(level Level, prefix, format string, args ...any) {
	levelMu.RLock()
	if level > currentLevel {
		levelMu.RUnlock()
		return
	}
	levelMu.RUnlock()

	sinkMu.RLock()
	currentSink := sink
	sinkMu.RUnlock()

	currentSink.Log(level, strings.ToUpper(prefix), format, args...)
}

func Debugf(format string, args ...any) { logf(LevelDebug, "debug", format, args...) }
func Infof(format string, args ...any)  { logf(LevelInfo, "info", format, args...) }
func Warnf(format string, args ...any)  { logf(LevelWarn, "warn", format, args...) }
func Errorf(format string, args ...any) { logf(LevelError, "error", format, args...) }

func NewStreamWriter(prefix string, defaultLevel Level) io.Writer {
	return &streamWriter{
		prefix:       prefix,
		defaultLevel: defaultLevel,
	}
}

const (
	syslogTag = "[VPNER]"
)

var syslogPaths = []string{
	"/dev/log",
	"/dev/syslog",
	"/var/run/syslog",
}

type logSink interface {
	Log(level Level, prefix, format string, args ...any)
}

type fallbackSink struct {
	logger *log.Logger
}

func newFallbackSink() *fallbackSink {
	return &fallbackSink{logger: log.New(os.Stderr, "", log.LstdFlags)}
}

func (s *fallbackSink) Log(level Level, prefix, format string, args ...any) {
	s.logger.Printf("%s [%s] %s", syslogTag, prefix, formatMessage(format, args...))
}

type syslogSink struct {
	writer *syslog.Writer
}

type streamWriter struct {
	mu           sync.Mutex
	prefix       string
	defaultLevel Level
	buffer       strings.Builder
}

func newSyslogSink() (*syslogSink, error) {
	var lastErr error
	for _, path := range syslogPaths {
		writer, err := dialSyslog(path)
		if err == nil {
			return &syslogSink{writer: writer}, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return nil, lastErr
}

func dialSyslog(path string) (*syslog.Writer, error) {
	var lastErr error
	for _, network := range []string{"unixgram", "unix"} {
		writer, err := syslog.Dial(network, path, syslog.LOG_DAEMON|syslog.LOG_INFO, syslogTag)
		if err == nil {
			return writer, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return nil, fmt.Errorf("%s: %w", path, lastErr)
}

func (s *syslogSink) Log(level Level, prefix, format string, args ...any) {
	message := "[" + prefix + "] " + formatMessage(format, args...)
	switch level {
	case LevelDebug:
		_ = s.writer.Debug(message)
	case LevelInfo:
		_ = s.writer.Info(message)
	case LevelWarn:
		_ = s.writer.Warning(message)
	default:
		_ = s.writer.Err(message)
	}
}

func formatMessage(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(fmt.Sprintf(format, args...)), "\n"), "\r"))
}

func (w *streamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buffer.Write(p)
	data := w.buffer.String()
	lines := strings.Split(data, "\n")
	w.buffer.Reset()

	last := len(lines) - 1
	for i, line := range lines {
		if i == last && !strings.HasSuffix(data, "\n") {
			w.buffer.WriteString(line)
			continue
		}
		w.logLine(line)
	}

	return len(p), nil
}

func (w *streamWriter) logLine(line string) {
	line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if line == "" {
		return
	}

	level := detectLineLevel(line, w.defaultLevel)
	if w.prefix != "" {
		line = "[" + w.prefix + "] " + line
	}
	logf(level, levelName(level), "%s", line)
}

func detectLineLevel(line string, fallback Level) Level {
	switch {
	case strings.Contains(line, "[Debug]"):
		return LevelDebug
	case strings.Contains(line, "[Info]"):
		return LevelInfo
	case strings.Contains(line, "[Warning]"), strings.Contains(line, "[Warn]"):
		return LevelWarn
	case strings.Contains(line, "[Error]"):
		return LevelError
	default:
		return fallback
	}
}

func levelName(level Level) string {
	switch level {
	case LevelDebug:
		return "debug"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}
