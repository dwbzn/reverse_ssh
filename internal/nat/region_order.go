package nat

import (
	"sort"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

func orderedRegionIDs(derpMap *vderp.Map) []int {
	if derpMap == nil || len(derpMap.Regions) == 0 {
		return nil
	}

	regionOrder := make([]int, 0, len(derpMap.Regions))
	for regionID := range derpMap.Regions {
		regionOrder = append(regionOrder, regionID)
	}
	sort.Ints(regionOrder)
	return regionOrder
}
