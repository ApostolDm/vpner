//go:build linux

package main

import (
	"syscall"

	"github.com/ApostolDmitry/vpner/internal/logx"
)

const wantOpenFiles = 65536

func raiseOpenFilesLimit() {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		logx.Warnf("open files limit: %v", err)
		return
	}
	want := lim
	if want.Max < wantOpenFiles {
		want.Max = wantOpenFiles
	}
	want.Cur = want.Max
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &want); err != nil {
		want.Max, want.Cur = lim.Max, lim.Max
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &want); err != nil {
			logx.Warnf("open files limit stays at %d/%d: %v", lim.Cur, lim.Max, err)
			return
		}
	}
	if want.Cur < 4096 {
		logx.Warnf("open files limit is only %d: xray will hit 'too many open files' under load", want.Cur)
		return
	}
	logx.Infof("open files limit: %d (was %d/%d)", want.Cur, lim.Cur, lim.Max)
}
