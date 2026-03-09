package network

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/ApostolDmitry/vpner/internal/common/logging"
)

type iptablesBatch struct {
	cmd   string
	table string
	buf   bytes.Buffer
}

func newBatch(cmd, table string) *iptablesBatch {
	b := &iptablesBatch{
		cmd:   cmd,
		table: table,
	}
	b.buf.WriteString("*" + table + "\n")
	return b
}

func (b *iptablesBatch) Add(rule string) {
	b.buf.WriteString(rule)
	b.buf.WriteByte('\n')
}

func (b *iptablesBatch) Commit() error {

	b.buf.WriteString("COMMIT\n")

	restore := "iptables-restore"
	if b.cmd == "ip6tables" {
		restore = "ip6tables-restore"
	}

	logging.Infof(
		"iptables batch apply (cmd=%s table=%s)",
		restore,
		b.table,
	)

	logging.Debugf(
		"iptables batch rules:\n%s",
		b.buf.String(),
	)

	cmd := exec.Command(restore, "--noflush")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	go func() {
		defer stdin.Close()
		stdin.Write(b.buf.Bytes())
	}()

	out, err := cmd.CombinedOutput()
	if err != nil {
		logging.Errorf(
			"%s failed (table=%s): %s",
			restore,
			b.table,
			string(out),
		)
		return fmt.Errorf("%s failed: %v (%s)", restore, err, out)
	}

	return nil
}
