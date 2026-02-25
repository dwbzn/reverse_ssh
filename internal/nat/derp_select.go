package nat

import (
	"fmt"
	"strings"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

type derpRegionCandidate struct {
	regionID int
	node     vderp.Node
}

// pickDERPNode is used by the server to choose a relay region.
// Region selection is deterministic to keep transport setup predictable.
func pickDERPNode(derpMap *vderp.Map, preferredRegion int) (int, vderp.Node, error) {
	candidates, err := orderedDERPRegionCandidates(derpMap, preferredRegion)
	if err != nil {
		return 0, vderp.Node{}, err
	}

	selected := candidates[0]
	return selected.regionID, selected.node, nil
}

// pickDERPNodeForClient mirrors server selection to avoid mismatches.
func pickDERPNodeForClient(derpMap *vderp.Map, preferredRegion int) (int, vderp.Node, error) {
	return pickDERPNode(derpMap, preferredRegion)
}

func orderedDERPRegionCandidates(derpMap *vderp.Map, preferredRegion int) ([]derpRegionCandidate, error) {
	if derpMap == nil || len(derpMap.Regions) == 0 {
		return nil, fmt.Errorf("derp map has no regions")
	}

	tryRegions := orderedRegionIDs(derpMap, preferredRegion)
	candidates := make([]derpRegionCandidate, 0, len(tryRegions))
	for _, regionID := range tryRegions {
		region, ok := derpMap.Regions[regionID]
		if !ok {
			continue
		}

		node, ok := firstUsableNode(region.Nodes)
		if !ok {
			continue
		}

		candidates = append(candidates, derpRegionCandidate{
			regionID: regionID,
			node:     node,
		})
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("derp map contains no usable node")
	}

	return candidates, nil
}

func firstUsableNode(nodes []vderp.Node) (vderp.Node, bool) {
	for _, node := range nodes {
		node, ok := normaliseDERPNode(node)
		if ok {
			return node, true
		}
	}
	return vderp.Node{}, false
}

func normaliseDERPNode(node vderp.Node) (vderp.Node, bool) {
	if strings.TrimSpace(node.HostName) == "" {
		return vderp.Node{}, false
	}
	if node.DERPPort == 0 {
		node.DERPPort = 443
	}
	if node.STUNPort == 0 {
		node.STUNPort = 3478
	}
	return node, true
}
