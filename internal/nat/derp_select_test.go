package nat

import (
	"testing"
	"time"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

func TestPickNearestDERPNodeFallsBackToNextUsableRegion(t *testing.T) {
	derpMap := &vderp.Map{
		Regions: map[int]vderp.Region{
			1: {
				RegionID: 1,
				Nodes: []vderp.Node{{
					Name:             "region-one",
					RegionID:         1,
					HostName:         "derp-one.example",
					DERPPort:         443,
					InsecureForTests: true,
				}},
			},
			2: {
				RegionID: 2,
				Nodes: []vderp.Node{{
					Name:             "region-two-invalid",
					RegionID:         2,
					HostName:         "",
					DERPPort:         443,
					InsecureForTests: true,
				}},
			},
		},
	}

	regionID, selected, err := pickNearestDERPNode(derpMap)
	if err != nil {
		t.Fatalf("pickNearestDERPNode() error = %v", err)
	}
	if regionID != 1 {
		t.Fatalf("regionID = %d, want %d", regionID, 1)
	}
	if selected.RegionID != 1 {
		t.Fatalf("selected region = %d, want %d", selected.RegionID, 1)
	}
}

func TestPickNearestDERPNodePrefersLowestLatency(t *testing.T) {
	derpMap := &vderp.Map{
		Regions: map[int]vderp.Region{
			1: {
				RegionID: 1,
				Nodes: []vderp.Node{{
					Name:             "region-one",
					RegionID:         1,
					HostName:         "derp-one.example",
					DERPPort:         443,
					InsecureForTests: true,
				}},
			},
			2: {
				RegionID: 2,
				Nodes: []vderp.Node{{
					Name:             "region-two",
					RegionID:         2,
					HostName:         "derp-two.example",
					DERPPort:         443,
					InsecureForTests: true,
				}},
			},
			3: {
				RegionID: 3,
				Nodes: []vderp.Node{{
					Name:             "region-three",
					RegionID:         3,
					HostName:         "derp-three.example",
					DERPPort:         443,
					InsecureForTests: true,
				}},
			},
		},
	}

	originalProbe := measureDERPNodeLatencyFunc
	measureDERPNodeLatencyFunc = func(node vderp.Node, _ time.Duration) time.Duration {
		switch node.HostName {
		case "derp-one.example":
			return 32 * time.Millisecond
		case "derp-two.example":
			return 8 * time.Millisecond
		case "derp-three.example":
			return 20 * time.Millisecond
		default:
			return unreachableDERPLatency
		}
	}
	t.Cleanup(func() {
		measureDERPNodeLatencyFunc = originalProbe
	})

	regionID, selected, err := pickNearestDERPNode(derpMap)
	if err != nil {
		t.Fatalf("pickNearestDERPNode() error = %v", err)
	}
	if regionID != 2 {
		t.Fatalf("regionID = %d, want %d", regionID, 2)
	}
	if selected.RegionID != 2 {
		t.Fatalf("selected region = %d, want %d", selected.RegionID, 2)
	}
}
