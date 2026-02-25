package nat

import (
	"testing"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

func TestPickDERPNodePrefersHintWhenUsable(t *testing.T) {
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
		},
	}

	regionID, selected, err := pickDERPNode(derpMap, 2)
	if err != nil {
		t.Fatalf("pickDERPNode() error = %v", err)
	}
	if regionID != 2 {
		t.Fatalf("regionID = %d, want %d", regionID, 2)
	}
	if selected.RegionID != 2 {
		t.Fatalf("selected region = %d, want %d", selected.RegionID, 2)
	}
}

func TestPickDERPNodeFallsBackToNextUsableRegion(t *testing.T) {
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

	regionID, selected, err := pickDERPNode(derpMap, 2)
	if err != nil {
		t.Fatalf("pickDERPNode() error = %v", err)
	}
	if regionID != 1 {
		t.Fatalf("regionID = %d, want %d", regionID, 1)
	}
	if selected.RegionID != 1 {
		t.Fatalf("selected region = %d, want %d", selected.RegionID, 1)
	}
}

func TestPickDERPNodeForClientMatchesServerSelection(t *testing.T) {
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

	serverRegion, _, err := pickDERPNode(derpMap, 3)
	if err != nil {
		t.Fatalf("pickDERPNode() error = %v", err)
	}
	clientRegion, _, err := pickDERPNodeForClient(derpMap, 3)
	if err != nil {
		t.Fatalf("pickDERPNodeForClient() error = %v", err)
	}
	if clientRegion != serverRegion {
		t.Fatalf("client region = %d, want %d", clientRegion, serverRegion)
	}
}
