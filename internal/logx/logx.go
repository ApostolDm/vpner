package logx

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

func Recover(where string) {
	if r := recover(); r != nil {
		Errorf("panic in %s: %v\n%s", where, r, debug.Stack())
	}
}

type Event struct {
	UnixMs  int64
	Level   string
	Message string
}

const eventRingCap = 50

var (
	eventsMu  sync.Mutex
	events    [eventRingCap]Event
	eventsLen int
	eventsPos int
)

func recordEvent(l Level, msg string) {
	eventsMu.Lock()
	events[eventsPos] = Event{UnixMs: time.Now().UnixMilli(), Level: LevelTag(l), Message: msg}
	eventsPos = (eventsPos + 1) % eventRingCap
	if eventsLen < eventRingCap {
		eventsLen++
	}
	eventsMu.Unlock()
}

func Recent() []Event {
	eventsMu.Lock()
	defer eventsMu.Unlock()
	out := make([]Event, 0, eventsLen)
	start := (eventsPos - eventsLen + eventRingCap) % eventRingCap
	for i := 0; i < eventsLen; i++ {
		out = append(out, events[(start+i)%eventRingCap])
	}
	return out
}

type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

const Tag = "[VPNER]"

type Sink interface {
	Log(level Level, msg string)
}

var (
	mu    sync.RWMutex
	level      = LevelInfo
	out   Sink = stderrSink()
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

func SetSink(s Sink) {
	if s == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	out = s
}

func Debugf(format string, a ...any) { emit(LevelDebug, format, a...) }
func Infof(format string, a ...any)  { emit(LevelInfo, format, a...) }
func Warnf(format string, a ...any)  { emit(LevelWarn, format, a...) }
func Errorf(format string, a ...any) { emit(LevelError, format, a...) }

func emit(l Level, format string, a ...any) {
	mu.RLock()
	defer mu.RUnlock()
	notable := l <= LevelWarn
	if l > level && !notable {
		return
	}
	msg := message(format, a...)
	if notable {
		recordEvent(l, msg)
	}
	if l > level {
		return
	}
	out.Log(l, msg)
}

func message(format string, a ...any) string {
	if len(a) == 0 {
		return format
	}
	return strings.TrimRight(fmt.Sprintf(format, a...), "\r\n")
}

func LevelTag(l Level) string {
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

type stderrLogger struct{ l *log.Logger }

func stderrSink() *stderrLogger { return &stderrLogger{l: log.New(os.Stderr, "", log.LstdFlags)} }

func (s *stderrLogger) Log(l Level, msg string) {
	s.l.Printf("%s [%s] %s", Tag, LevelTag(l), msg)
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
