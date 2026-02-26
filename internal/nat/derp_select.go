package nat

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

type derpRegionCandidate struct {
	regionID int
	node     vderp.Node
}

// pickDERPNode chooses a relay region.
func pickDERPNode(derpMap *vderp.Map, preferredRegion int) (int, vderp.Node, error) {
	candidates, err := orderedDERPRegionCandidates(derpMap, preferredRegion)
	if err != nil {
		return 0, vderp.Node{}, err
	}

	selected := candidates[0]
	return selected.regionID, selected.node, nil
}

func orderedDERPRegionCandidates(derpMap *vderp.Map, preferredRegion int) ([]derpRegionCandidate, error) {
	if derpMap == nil || len(derpMap.Regions) == 0 {
		return nil, fmt.Errorf("derp map has no regions")
	}

	tryRegions := orderedRegionIDs(derpMap, preferredRegion)
	if preferredRegion == 0 {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		rng.Shuffle(len(tryRegions), func(i, j int) {
			tryRegions[i], tryRegions[j] = tryRegions[j], tryRegions[i]
		})
	}

	candidates := make([]derpRegionCandidate, 0, len(tryRegions))
	for _, regionID := range tryRegions {
		region, ok := derpMap.Regions[regionID]
		if !ok {
			continue
		}

		node, ok := randomUsableNode(region.Nodes)
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

func randomUsableNode(nodes []vderp.Node) (vderp.Node, bool) {
	var usable []vderp.Node
	for _, node := range nodes {
		node, ok := normaliseDERPNode(node)
		if ok {
			usable = append(usable, node)
		}
	}
	if len(usable) == 0 {
		return vderp.Node{}, false
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	return usable[rng.Intn(len(usable))], true
}

func normaliseDERPNode(node vderp.Node) (vderp.Node, bool) {
	if strings.TrimSpace(node.HostName) == "" {
		return vderp.Node{}, false
	}
	if node.DERPPort == 0 {
		node.DERPPort = 443
	}
	return node, true
}
