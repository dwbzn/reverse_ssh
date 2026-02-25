package commands

import (
	"bytes"
	"strings"
	"testing"

	"github.com/NHAS/reverse_ssh/internal/terminal"
)

func TestLinkRejectsNATTransportCombinations(t *testing.T) {
	line := terminal.ParseLine("link --nat --ws", 0)
	tty := bytes.NewBuffer(nil)

	err := (&link{}).Run(nil, tty, line)
	if err == nil {
		t.Fatalf("Run() should fail for mixed nat/ws transport flags")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "nat") {
		t.Fatalf("Run() error = %q, expected nat mention", err.Error())
	}
}

func TestSelectedTransportFlagsSingleSelection(t *testing.T) {
	line := terminal.ParseLine("link --https", 0)
	selected := selectedTransportFlags(line)

	if len(selected) != 1 {
		t.Fatalf("selected transport count = %d, want 1", len(selected))
	}
	if selected[0].flag != "https" {
		t.Fatalf("selected flag = %q, want %q", selected[0].flag, "https")
	}
	if selected[0].scheme != "https://" {
		t.Fatalf("selected scheme = %q, want %q", selected[0].scheme, "https://")
	}
}

func TestSelectedTransportFlagsNATHasNoSchemePrefix(t *testing.T) {
	line := terminal.ParseLine("link --nat", 0)
	selected := selectedTransportFlags(line)

	if len(selected) != 1 {
		t.Fatalf("selected transport count = %d, want 1", len(selected))
	}
	if selected[0].flag != "nat" {
		t.Fatalf("selected flag = %q, want %q", selected[0].flag, "nat")
	}
	if selected[0].scheme != "" {
		t.Fatalf("selected scheme = %q, want empty", selected[0].scheme)
	}
}
