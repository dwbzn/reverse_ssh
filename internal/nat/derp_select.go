package nat

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

type derpRegionCandidate struct {
	regionID int
	node     vderp.Node
	latency  time.Duration
}

const (
	derpLatencyProbeTimeout     = 750 * time.Millisecond
	derpLatencyProbeConcurrency = 8
	unreachableDERPLatency      = 24 * time.Hour
)

var measureDERPNodeLatencyFunc = measureDERPNodeLatency

// pickNearestDERPNode chooses the lowest-latency relay region.
func pickNearestDERPNode(derpMap *vderp.Map) (int, vderp.Node, error) {
	candidates, err := orderedDERPRegionCandidatesStable(derpMap)
	if err != nil {
		return 0, vderp.Node{}, err
	}

	rankDERPRegionCandidatesByLatency(candidates)
	selected := candidates[0]
	return selected.regionID, selected.node, nil
}

func orderedDERPRegionCandidatesStable(derpMap *vderp.Map) ([]derpRegionCandidate, error) {
	if derpMap == nil || len(derpMap.Regions) == 0 {
		return nil, fmt.Errorf("derp map has no regions")
	}

	tryRegions := orderedRegionIDs(derpMap)
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
			latency:  unreachableDERPLatency,
		})
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("derp map contains no usable node")
	}

	return candidates, nil
}

func firstUsableNode(nodes []vderp.Node) (vderp.Node, bool) {
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

	sort.Slice(usable, func(i, j int) bool {
		if usable[i].HostName != usable[j].HostName {
			return usable[i].HostName < usable[j].HostName
		}
		if usable[i].DERPPort != usable[j].DERPPort {
			return usable[i].DERPPort < usable[j].DERPPort
		}
		return usable[i].Name < usable[j].Name
	})

	return usable[0], true
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

func rankDERPRegionCandidatesByLatency(candidates []derpRegionCandidate) {
	if len(candidates) <= 1 {
		return
	}

	type probeResult struct {
		index   int
		latency time.Duration
	}

	sem := make(chan struct{}, derpLatencyProbeConcurrency)
	results := make(chan probeResult, len(candidates))
	var wg sync.WaitGroup

	for i := range candidates {
		candidates[i].latency = unreachableDERPLatency
	}

	for i, candidate := range candidates {
		wg.Add(1)
		go func(index int, node vderp.Node) {
			defer wg.Done()

			sem <- struct{}{}
			latency := measureDERPNodeLatencyFunc(node, derpLatencyProbeTimeout)
			<-sem

			results <- probeResult{index: index, latency: latency}
		}(i, candidate.node)
	}

	wg.Wait()
	close(results)

	for result := range results {
		candidates[result.index].latency = result.latency
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].latency == candidates[j].latency {
			return candidates[i].regionID < candidates[j].regionID
		}
		return candidates[i].latency < candidates[j].latency
	})
}

func measureDERPNodeLatency(node vderp.Node, timeout time.Duration) time.Duration {
	port := node.DERPPort
	if port == 0 {
		port = 443
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(node.HostName, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return unreachableDERPLatency
	}
	_ = conn.Close()

	latency := time.Since(start)
	if latency <= 0 {
		return time.Microsecond
	}
	return latency
}
