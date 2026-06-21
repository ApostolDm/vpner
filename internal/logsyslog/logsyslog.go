//go:build !windows && !plan9

package logsyslog

import (
	"log/syslog"
	"os"

	"github.com/ApostolDmitry/vpner/internal/logx"
)

var paths = []string{"/dev/log", "/dev/syslog", "/var/run/syslog"}

func Configure() error {
	w, err := dial()
	if err != nil {
		return err
	}
	logx.SetSink(&sink{w: w})
	return nil
}

func dial() (*syslog.Writer, error) {
	var lastErr error
	for _, path := range paths {
		for _, network := range []string{"unixgram", "unix"} {
			if w, err := syslog.Dial(network, path, syslog.LOG_DAEMON|syslog.LOG_INFO, logx.Tag); err == nil {
				return w, nil
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

type sink struct{ w *syslog.Writer }

func (s *sink) Log(l logx.Level, msg string) {
	switch l {
	case logx.LevelDebug:
		_ = s.w.Debug(msg)
	case logx.LevelInfo:
		_ = s.w.Info(msg)
	case logx.LevelWarn:
		_ = s.w.Warning(msg)
	default:
		_ = s.w.Err(msg)
	}
}
