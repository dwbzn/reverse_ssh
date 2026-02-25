package nat

import (
	"sort"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

func orderedRegionIDs(derpMap *vderp.Map, preferredRegion int) []int {
	if derpMap == nil || len(derpMap.Regions) == 0 {
		return nil
	}

	regionOrder := make([]int, 0, len(derpMap.Regions))
	if preferredRegion > 0 {
		if _, ok := derpMap.Regions[preferredRegion]; ok {
			regionOrder = append(regionOrder, preferredRegion)
		}
	}

	otherRegions := make([]int, 0, len(derpMap.Regions))
	for regionID := range derpMap.Regions {
		if regionID == preferredRegion {
			continue
		}
		otherRegions = append(otherRegions, regionID)
	}
	sort.Ints(otherRegions)

	return append(regionOrder, otherRegions...)
}
