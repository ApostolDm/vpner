package logx

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

const syslogTag = "[VPNER]"

var syslogPaths = []string{"/dev/log", "/dev/syslog", "/var/run/syslog"}

var (
	mu    sync.RWMutex
	level      = LevelInfo
	out   sink = stderrSink()
)

func SetLevel(name string) {
	mu.Lock()
	defer mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		level = LevelDebug
	case "warn", "warning":
		level = LevelWarn
	case "error":
		level = LevelError
	default:
		level = LevelInfo
	}
}

func Configure() error {
	s, err := dialSyslog()
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		out = stderrSink()
		return err
	}
	out = s
	return nil
}

func Debugf(format string, a ...any) { emit(LevelDebug, format, a...) }
func Infof(format string, a ...any)  { emit(LevelInfo, format, a...) }
func Warnf(format string, a ...any)  { emit(LevelWarn, format, a...) }
func Errorf(format string, a ...any) { emit(LevelError, format, a...) }

func emit(l Level, format string, a ...any) {
	mu.RLock()
	defer mu.RUnlock()
	if l > level {
		return
	}
	out.log(l, message(format, a...))
}

func message(format string, a ...any) string {
	if len(a) == 0 {
		return format
	}
	return strings.TrimRight(fmt.Sprintf(format, a...), "\r\n")
}

func levelTag(l Level) string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

type sink interface {
	log(l Level, msg string)
}

type stderr struct{ l *log.Logger }

func stderrSink() *stderr { return &stderr{l: log.New(os.Stderr, "", log.LstdFlags)} }

func (s *stderr) log(l Level, msg string) {
	s.l.Printf("%s [%s] %s", syslogTag, levelTag(l), msg)
}

type syslogSink struct{ w *syslog.Writer }

func dialSyslog() (*syslogSink, error) {
	var lastErr error
	for _, path := range syslogPaths {
		for _, network := range []string{"unixgram", "unix"} {
			if w, err := syslog.Dial(network, path, syslog.LOG_DAEMON|syslog.LOG_INFO, syslogTag); err == nil {
				return &syslogSink{w: w}, nil
			} else {
				lastErr = err
			}
		}
	}
	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return nil, lastErr
}

func (s *syslogSink) log(l Level, msg string) {
	switch l {
	case LevelDebug:
		_ = s.w.Debug(msg)
	case LevelInfo:
		_ = s.w.Info(msg)
	case LevelWarn:
		_ = s.w.Warning(msg)
	default:
		_ = s.w.Err(msg)
	}
}

func NewStreamWriter(prefix string, defaultLevel Level) io.Writer {
	return &streamWriter{prefix: prefix, defaultLevel: defaultLevel}
}

type streamWriter struct {
	mu           sync.Mutex
	prefix       string
	defaultLevel Level
	buf          strings.Builder
}

func (w *streamWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf.Write(p)
	data := w.buf.String()
	w.buf.Reset()

	lines := strings.Split(data, "\n")
	last := len(lines) - 1
	for i, line := range lines {
		if i == last && !strings.HasSuffix(data, "\n") {
			w.buf.WriteString(line)
			continue
		}
		w.logLine(line)
	}
	return len(p), nil
}

func (w *streamWriter) logLine(line string) {
	line = strings.TrimRight(line, "\r")
	if strings.TrimSpace(line) == "" {
		return
	}
	l := w.defaultLevel
	switch {
	case strings.Contains(line, "[Debug]"):
		l = LevelDebug
	case strings.Contains(line, "[Info]"):
		l = LevelInfo
	case strings.Contains(line, "[Warning]"), strings.Contains(line, "[Warn]"):
		l = LevelWarn
	case strings.Contains(line, "[Error]"):
		l = LevelError
	}
	if w.prefix != "" {
		line = "[" + w.prefix + "] " + line
	}
	emit(l, "%s", line)
}
