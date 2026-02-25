package nat

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

const (
	stunBindingRequest  = uint16(0x0001)
	stunBindingSuccess  = uint16(0x0101)
	stunAttrMapped      = uint16(0x0001)
	stunAttrXORMapped   = uint16(0x0020)
	stunMagicCookie     = uint32(0x2112A442)
	stunHeaderLength    = 20
	stunTransactionSize = 12

	stunAttemptCount = 2
	stunMaxNodes     = 8
)

func discoverSTUNCandidateFromMap(derpMap *vderp.Map, preferredRegion int, localPort int) (string, error) {
	nodes := stunCandidateNodes(derpMap, preferredRegion)
	if len(nodes) == 0 {
		return "", fmt.Errorf("no stun nodes available")
	}
	if len(nodes) > stunMaxNodes {
		nodes = nodes[:stunMaxNodes]
	}

	deadline := time.Now().Add(2500 * time.Millisecond)
	var lastErr error
	for _, node := range nodes {
		for attempt := 0; attempt < stunAttemptCount; attempt++ {
			if time.Now().After(deadline) {
				if lastErr == nil {
					lastErr = fmt.Errorf("stun discovery deadline exceeded")
				}
				return "", lastErr
			}
			timeout := 800*time.Millisecond + time.Duration(attempt)*500*time.Millisecond
			candidate, err := discoverSTUNCandidate(node, localPort, timeout)
			if err == nil && candidate != "" {
				return candidate, nil
			}
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("stun candidate discovery failed")
	}
	return "", lastErr
}

func stunCandidateNodes(derpMap *vderp.Map, preferredRegion int) []vderp.Node {
	if derpMap == nil || len(derpMap.Regions) == 0 {
		return nil
	}

	regionOrder := orderedRegionIDs(derpMap, preferredRegion)

	var nodes []vderp.Node
	for _, regionID := range regionOrder {
		region, ok := derpMap.Regions[regionID]
		if !ok {
			continue
		}
		for _, node := range region.Nodes {
			if node.HostName == "" {
				continue
			}
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func discoverSTUNCandidate(node vderp.Node, localPort int, timeout time.Duration) (string, error) {
	stunPort := node.STUNPort
	if stunPort == 0 {
		stunPort = 3478
	}
	if node.HostName == "" {
		return "", fmt.Errorf("stun host is empty")
	}

	request, txID, err := buildSTUNBindingRequest()
	if err != nil {
		return "", err
	}

	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: localPort}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(node.HostName, strconv.Itoa(stunPort)))
	if err != nil {
		return "", err
	}

	if _, err := conn.WriteToUDP(request, remoteAddr); err != nil {
		return "", err
	}

	buf := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return "", err
	}

	addr, err := parseSTUNBindingResponse(buf[:n], txID)
	if err != nil {
		return "", err
	}

	return addr.String(), nil
}

func buildSTUNBindingRequest() ([]byte, [stunTransactionSize]byte, error) {
	var txID [stunTransactionSize]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, txID, err
	}

	packet := make([]byte, stunHeaderLength)
	binary.BigEndian.PutUint16(packet[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(packet[2:4], 0)
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], txID[:])
	return packet, txID, nil
}

func parseSTUNBindingResponse(packet []byte, txID [stunTransactionSize]byte) (netip.AddrPort, error) {
	if len(packet) < stunHeaderLength {
		return netip.AddrPort{}, fmt.Errorf("short stun response")
	}
	messageType := binary.BigEndian.Uint16(packet[0:2])
	if messageType != stunBindingSuccess {
		return netip.AddrPort{}, fmt.Errorf("unexpected stun response type 0x%x", messageType)
	}
	messageLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if len(packet) < stunHeaderLength+messageLength {
		return netip.AddrPort{}, fmt.Errorf("truncated stun response")
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return netip.AddrPort{}, fmt.Errorf("invalid stun magic cookie")
	}
	if !bytes.Equal(packet[8:20], txID[:]) {
		return netip.AddrPort{}, fmt.Errorf("stun transaction id mismatch")
	}

	attrs := packet[20 : 20+messageLength]
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		attrs = attrs[4:]
		if len(attrs) < attrLen {
			return netip.AddrPort{}, fmt.Errorf("truncated stun attribute")
		}
		value := attrs[:attrLen]

		switch attrType {
		case stunAttrXORMapped:
			if addr, ok := parseSTUNXORMappedAddress(value, txID); ok {
				return addr, nil
			}
		case stunAttrMapped:
			if addr, ok := parseSTUNMappedAddress(value); ok {
				return addr, nil
			}
		}

		padded := attrLen
		if rem := padded % 4; rem != 0 {
			padded += 4 - rem
		}
		if len(attrs) < padded {
			return netip.AddrPort{}, fmt.Errorf("truncated padded stun attribute")
		}
		attrs = attrs[padded:]
	}

	return netip.AddrPort{}, fmt.Errorf("stun response missing mapped address")
}

func parseSTUNMappedAddress(value []byte) (netip.AddrPort, bool) {
	if len(value) < 4 {
		return netip.AddrPort{}, false
	}
	family := value[1]
	port := binary.BigEndian.Uint16(value[2:4])

	switch family {
	case 0x01: // IPv4
		if len(value) < 8 {
			return netip.AddrPort{}, false
		}
		var ip [4]byte
		copy(ip[:], value[4:8])
		return netip.AddrPortFrom(netip.AddrFrom4(ip), port), true
	case 0x02: // IPv6
		if len(value) < 20 {
			return netip.AddrPort{}, false
		}
		var ip [16]byte
		copy(ip[:], value[4:20])
		return netip.AddrPortFrom(netip.AddrFrom16(ip), port), true
	}
	return netip.AddrPort{}, false
}

func parseSTUNXORMappedAddress(value []byte, txID [stunTransactionSize]byte) (netip.AddrPort, bool) {
	if len(value) < 4 {
		return netip.AddrPort{}, false
	}
	family := value[1]
	xPort := binary.BigEndian.Uint16(value[2:4])
	port := xPort ^ uint16(stunMagicCookie>>16)

	switch family {
	case 0x01: // IPv4
		if len(value) < 8 {
			return netip.AddrPort{}, false
		}
		cookie := make([]byte, 4)
		binary.BigEndian.PutUint32(cookie, stunMagicCookie)
		var ip [4]byte
		for i := range ip {
			ip[i] = value[4+i] ^ cookie[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom4(ip), port), true
	case 0x02: // IPv6
		if len(value) < 20 {
			return netip.AddrPort{}, false
		}
		mask := make([]byte, 16)
		binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
		copy(mask[4:], txID[:])

		var ip [16]byte
		for i := range ip {
			ip[i] = value[4+i] ^ mask[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom16(ip), port), true
	}
	return netip.AddrPort{}, false
}
