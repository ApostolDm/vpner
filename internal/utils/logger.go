package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const logFile = "/opt/home/go.log"
const logTag = "VPNER"

func logToSyslog(tag, priority, message string) error {
	cmd := exec.Command("logger", "-t", tag)
	if priority != "" {
		cmd.Args = append(cmd.Args, "-p", priority)
	}
	cmd.Args = append(cmd.Args, message)
	return cmd.Run()
}

func logToFile(tag, message string) error {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("can't open log file: %w", err)
	}
	defer f.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("%s [%s] %s\n", timestamp, tag, message)

	if _, err := f.WriteString(logMessage); err != nil {
		return fmt.Errorf("can't write to log file: %w", err)
	}
	return nil
}

func writeLog(priority string, format string, args ...any) error {
	message := fmt.Sprintf(format, args...)

	message = strings.TrimSpace(message)

	syslogErr := logToSyslog(logTag, priority, message)
	fileErr := logToFile(logTag, message)

	if syslogErr != nil || fileErr != nil {
		return fmt.Errorf("logging error (syslog: %v, file: %v)", syslogErr, fileErr)
	}
	return nil
}

func Log(args ...any) error {
	return writeLog("", "%v", args...)
}

func LogError(args ...any) error {
	return writeLog("err", "%v", args...)
}

func LogF(format string, args ...any) error {
	return writeLog("", format, args...)
}

func LogErrorF(format string, args ...any) error {
	return writeLog("err", format, args...)
}
