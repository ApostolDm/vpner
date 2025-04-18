package utils

import (
	"fmt"
	"os/exec"
	"strings"
)

const logTag = "VPNER"

func logToSyslog(tag, priority, message string) error {
	cmd := exec.Command("logger", "-t", tag)
	if priority != "" {
		cmd.Args = append(cmd.Args, "-p", priority)
	}
	cmd.Args = append(cmd.Args, message)
	return cmd.Run()
}
func writeLog(priority string, format string, args ...any) error {
	message := fmt.Sprintf(format, args...)

	message = strings.TrimSpace(message)

	return logToSyslog(logTag, priority, message)
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
