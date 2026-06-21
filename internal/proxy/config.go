package proxy

import "encoding/json"

func renderConfig(l *Link, inboundPort int, tproxy bool) ([]byte, jobj, error) {
	outbound := buildOutbound(l)
	cfg := jobj{
		"inbounds":  []jobj{buildInbound(inboundPort, tproxy)},
		"outbounds": []jobj{outbound},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return data, outbound, nil
}

func buildInbound(port int, tproxy bool) jobj {
	in := jobj{
		"port":     port,
		"protocol": "dokodemo-door",
		"settings": jobj{
			"network":        "tcp,udp",
			"followRedirect": true,
			"timeout":        0,
		},
		"sniffing": jobj{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		},
	}
	if tproxy {
		in["listen"] = "0.0.0.0"
		in["streamSettings"] = jobj{
			"sockopt": jobj{"tproxy": "tproxy"},
		}
	}
	return in
}

func normalizeVLESSEncryption(outbounds []jobj) {
	for _, ob := range outbounds {
		if proto, _ := ob["protocol"].(string); proto != "vless" {
			continue
		}
		settings, _ := ob["settings"].(map[string]any)
		vnext, _ := settings["vnext"].([]any)
		for _, entry := range vnext {
			em, _ := entry.(map[string]any)
			users, _ := em["users"].([]any)
			for _, u := range users {
				um, ok := u.(map[string]any)
				if !ok {
					continue
				}
				if enc, _ := um["encryption"].(string); enc == "" {
					um["encryption"] = "none"
				}
			}
		}
	}
}
