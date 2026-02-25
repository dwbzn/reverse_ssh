package derpmap

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

type Map struct {
	Regions map[int]Region
}

type Region struct {
	RegionID   int
	RegionCode string
	RegionName string
	Nodes      []Node
}

type Node struct {
	Name             string
	RegionID         int
	HostName         string
	CertName         string
	IPv4             string
	IPv6             string
	STUNPort         int
	DERPPort         int
	InsecureForTests bool
}

type rawMap struct {
	Regions map[string]rawRegion `json:"Regions"`
}

type rawRegion struct {
	RegionID   int       `json:"RegionID"`
	RegionCode string    `json:"RegionCode"`
	RegionName string    `json:"RegionName"`
	Nodes      []rawNode `json:"Nodes"`
}

type rawNode struct {
	Name             string `json:"Name"`
	RegionID         int    `json:"RegionID"`
	HostName         string `json:"HostName"`
	CertName         string `json:"CertName"`
	IPv4             string `json:"IPv4"`
	IPv6             string `json:"IPv6"`
	STUNPort         int    `json:"STUNPort"`
	DERPPort         int    `json:"DERPPort"`
	InsecureForTests bool   `json:"InsecureForTests"`
}

func ParseJSON(data []byte) (*Map, error) {
	var raw rawMap
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if len(raw.Regions) == 0 {
		return nil, fmt.Errorf("derp map has no regions")
	}

	out := &Map{
		Regions: make(map[int]Region, len(raw.Regions)),
	}

	for key, region := range raw.Regions {
		id := region.RegionID
		if id == 0 {
			parsed, err := strconv.Atoi(key)
			if err != nil {
				return nil, fmt.Errorf("invalid region key %q", key)
			}
			id = parsed
		}
		nodes := make([]Node, 0, len(region.Nodes))
		for _, node := range region.Nodes {
			nodes = append(nodes, Node(node))
		}
		out.Regions[id] = Region{
			RegionID:   id,
			RegionCode: region.RegionCode,
			RegionName: region.RegionName,
			Nodes:      nodes,
		}
	}

	return out, nil
}

func (m *Map) FirstRegionID() int {
	if m == nil || len(m.Regions) == 0 {
		return 0
	}
	ids := make([]int, 0, len(m.Regions))
	for id := range m.Regions {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids[0]
}
