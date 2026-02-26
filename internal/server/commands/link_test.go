package commands

import (
	"bytes"
	"strings"
	"testing"

	"github.com/NHAS/reverse_ssh/internal/terminal"
)

func TestLinkRejectsTSTransportCombinations(t *testing.T) {
	line := terminal.ParseLine("link --ts --ws", 0)
	tty := bytes.NewBuffer(nil)

	err := (&link{}).Run(nil, tty, line)
	if err == nil {
		t.Fatalf("Run() should fail for mixed ts/ws transport flags")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ts") {
		t.Fatalf("Run() error = %q, expected ts mention", err.Error())
	}
}
