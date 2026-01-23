/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"encoding/json"
	"fmt"
	"golang.zx2c4.com/wireguard/windows/services"
	"net"
	"net/http"
	"time"
)

const dohURL = "https://cloudflare-dns.com/dns-query"

type dnsAnswer struct {
	Data string `json:"data"`
	Type int    `json:"type"`
}

type dnsResponse struct {
	Answer []dnsAnswer `json:"Answer"`
}

func resolveHostname(name string, port uint16) (resolvedEndpoint *Endpoint, err error) {
	ip := net.ParseIP(name)
	if ip != nil {
		return &Endpoint{Host: ip.String(), Port: port}, nil
	}

	maxTries := 10
	if services.StartedAtBoot() {
		maxTries *= 3
	}
	for i := 0; i < maxTries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 4)
		}
		resolvedEndpoint, err = resolveHostnameOnce(name, port)
		if err == nil {
			return
		}
	}
	return
}

func resolveHostnameOnce(name string, port uint16) (resolvedEndpoint *Endpoint, err error) {
	// Query A records
	aRecords, errA := dohResolveAll(name, "A")
	if errA == nil && len(aRecords) > 0 {
		return &Endpoint{Host: aRecords[0], Port: port}, nil
	}

	// Query AAAA records
	aaaaRecords, errAAAA := dohResolveAll(name, "AAAA")
	if errAAAA == nil && len(aaaaRecords) > 0 {
		for _, addr := range aaaaRecords {
			ip := net.ParseIP(addr)
			// Check for IP4P (Teredo-like) format: 2001:0000::/32 or similar custom mapping
			if ip != nil && len(ip) == net.IPv6len &&
				ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00 {

				// Extract port (bytes 10,11)
				ipPort := (uint16(ip[10]) << 8) | uint16(ip[11])
				// Extract IPv4 (bytes 12~15)
				v4Addr := net.IPv4(ip[12], ip[13], ip[14], ip[15])
				return &Endpoint{Host: v4Addr.String(), Port: ipPort}, nil
			}
		}
		// If no IP4P, just return the first AAAA as IPv6
		return &Endpoint{Host: aaaaRecords[0], Port: port}, nil
	}

	return nil, fmt.Errorf("no A or AAAA records found for %s", name)
}

func dohResolveAll(name string, qtype string) ([]string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", dohURL, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Add("name", name)
	q.Add("type", qtype)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var dr dnsResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, err
	}
	var results []string
	for _, ans := range dr.Answer {
		// A=1, AAAA=28
		if (qtype == "A" && ans.Type == 1) || (qtype == "AAAA" && ans.Type == 28) {
			results = append(results, ans.Data)
		}
	}
	return results, nil
}

func (config *Config) ResolveEndpoints() error {
	for i := range config.Peers {
		if config.Peers[i].Endpoint.IsEmpty() {
			continue
		}
		var err error
		resolvedEndpoint, err := resolveHostname(config.Peers[i].Endpoint.Host, config.Peers[i].Endpoint.Port)
		if err != nil || resolvedEndpoint == nil {
			return fmt.Errorf("failed to resolve endpoint: %w", err)
		}
		config.Peers[i].Endpoint = *resolvedEndpoint
	}
	return nil
}
