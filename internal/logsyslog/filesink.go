package logsyslog

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/logx"
)

type fileSink struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	backups  int
	f        *os.File
	size     int64
}

func ConfigureFile(path string, maxKB, backups int) error {
	if maxKB <= 0 {
		maxKB = 1024
	}
	if backups < 0 {
		backups = 0
	}
	s := &fileSink{path: path, maxBytes: int64(maxKB) * 1024, backups: backups}
	if err := s.reopen(false); err != nil {
		return err
	}
	logx.SetSink(s)
	return nil
}

func (s *fileSink) reopen(truncate bool) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if truncate {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(s.path, flags, 0o640)
	if err != nil {
		return err
	}
	s.f = f
	s.size = 0
	if info, err := f.Stat(); err == nil {
		s.size = info.Size()
	}
	return nil
}

func (s *fileSink) Log(l logx.Level, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		if err := s.reopen(false); err != nil {
			return
		}
	}
	line := fmt.Sprintf("%s %s [%s] %s\n", time.Now().Format("2006/01/02 15:04:05"), logx.Tag, logx.LevelTag(l), msg)
	n, err := s.f.WriteString(line)
	if err != nil {
		return
	}
	s.size += int64(n)
	if s.size >= s.maxBytes {
		s.rotate()
	}
}

func (s *fileSink) rotate() {
	_ = s.f.Close()
	if s.backups > 0 {
		_ = os.Remove(fmt.Sprintf("%s.%d", s.path, s.backups))
		for i := s.backups - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", s.path, i), fmt.Sprintf("%s.%d", s.path, i+1))
		}
		_ = os.Rename(s.path, s.path+".1")
	}
	if err := s.reopen(true); err != nil {
		s.f = nil
	}
}
