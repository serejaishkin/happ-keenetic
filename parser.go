package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type ServerConfig struct {
	SubID    string                 `json:"sub_id"`
	Tag      string                 `json:"tag"`
	Name     string                 `json:"name"`
	Address  string                 `json:"address"`
	Port     int                    `json:"port"`
	Protocol string                 `json:"protocol"`
	Outbound map[string]interface{} `json:"outbound"`
}

type SubMeta struct {
	ProfileTitle          string                    `json:"profile_title"`
	ProfileUpdateInterval string                    `json:"profile_update_interval"`
	SubscriptionUserinfo  string                    `json:"subscription_userinfo"`
	SupportURL            string                    `json:"support_url"`
	FallbackURL           string                    `json:"fallback_url"`
	Announce              string                    `json:"announce"`
	Servers               map[string][]ServerConfig `json:"servers"`
}

type SubscriptionResult struct {
	Servers               []ServerConfig
	ProfileTitle          string
	ProfileUpdateInterval string
	SubscriptionUserinfo  string
	SupportURL            string
	FallbackURL           string
	Announce              string
}

// ParseSubscription auto-detects format: sing-box JSON / xray JSON / base64 / plain text.
func ParseSubscription(data []byte) ([]ServerConfig, error) {
	text := string(data)
	text = strings.TrimSpace(text)

	// 1. JSON: sing-box native or xray/happ format
	if strings.HasPrefix(text, "[") || strings.HasPrefix(text, "{") {
		// Try sing-box native JSON first (Shape 1, 2, 3)
		if servers := tryParseSingboxJSON(data); len(servers) > 0 {
			return servers, nil
		}
		// Try xray/happ JSON format
		var arr []map[string]interface{}
		if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
			if _, ok := arr[0]["outbounds"]; ok {
				return parseJSONOutbounds(arr)
			}
		}
		var obj map[string]interface{}
		if err := json.Unmarshal(data, &obj); err == nil {
			if _, ok := obj["outbounds"]; ok {
				return parseJSONOutbounds([]map[string]interface{}{obj})
			}
		}
	}

	// 2. Base64
	if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
		text = string(decoded)
	}

	// 3. Plain text URI list
	return parsePlainText(text)
}

// tryParseSingboxJSON parses sing-box native subscription JSON (Shapes 1,2,3).
func tryParseSingboxJSON(data []byte) []ServerConfig {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}

	var flat []map[string]interface{}
	switch r := root.(type) {
	case map[string]interface{}:
		if list, ok := r["outbounds"].([]interface{}); ok {
			flat = collectObjects(list)
		}
	case []interface{}:
		for _, el := range r {
			obj, ok := el.(map[string]interface{})
			if !ok {
				continue
			}
			if list, ok := obj["outbounds"].([]interface{}); ok {
				flat = append(flat, collectObjects(list)...)
				continue
			}
			_, hasType := obj["type"].(string)
			_, hasTag := obj["tag"].(string)
			if hasType && hasTag {
				flat = append(flat, obj)
			}
		}
	}

	var servers []ServerConfig
	for i, ob := range flat {
		typ := strings.ToLower(getString(ob, "type"))
		if typ == "" {
			continue
		}
		if typ == "direct" || typ == "block" || typ == "dns" || typ == "selector" || typ == "urltest" {
			continue
		}
		server := getString(ob, "server")
		port := getInt(ob, "server_port")
		if server == "" || port == 0 {
			continue
		}
		tag := getString(ob, "tag")
		if tag == "" {
			tag = fmt.Sprintf("%s-%d", typ, i)
		}
		servers = append(servers, ServerConfig{
			Tag:      tag,
			Name:     tag,
			Address:  server,
			Port:     port,
			Protocol: typ,
			Outbound: ob,
		})
	}
	return servers
}

func collectObjects(list []interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(list))
	for _, el := range list {
		if obj, ok := el.(map[string]interface{}); ok {
			out = append(out, obj)
		}
	}
	return out
}

func parseJSONOutbounds(arr []map[string]interface{}) ([]ServerConfig, error) {
	var servers []ServerConfig
	for idx, item := range arr {
		remarks, _ := item["remarks"].(string)
		if remarks == "" {
			remarks = fmt.Sprintf("Server-%d", idx+1)
		}

		outboundsRaw, ok := item["outbounds"].([]interface{})
		if !ok || len(outboundsRaw) == 0 {
			continue
		}

		var proxyOutbound map[string]interface{}
		for _, o := range outboundsRaw {
			om, _ := o.(map[string]interface{})
			if om == nil {
				continue
			}
			tag, _ := om["tag"].(string)
			proto, _ := om["protocol"].(string)
			if tag != "direct" && tag != "block" && proto != "freedom" && proto != "blackhole" {
				proxyOutbound = om
				break
			}
		}
		if proxyOutbound == nil {
			continue
		}

		addr, port := extractAddrPort(proxyOutbound)

		srv := ServerConfig{
			Tag:      fmt.Sprintf("sub-%d-%s", idx, hashString(remarks)),
			Name:     remarks,
			Address:  addr,
			Port:     port,
			Protocol: getString(proxyOutbound, "protocol"),
			Outbound: proxyOutbound,
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

func parsePlainText(text string) ([]ServerConfig, error) {
	lines := strings.Split(text, "\n")
	var servers []ServerConfig
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		srv, err := parseURILine(line)
		if err != nil {
			continue
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

func parseURILine(line string) (ServerConfig, error) {
	if strings.HasPrefix(line, "vless://") {
		return parseVLESS(line)
	}
	if strings.HasPrefix(line, "vmess://") {
		return parseVMess(line)
	}
	if strings.HasPrefix(line, "trojan://") {
		return parseTrojan(line)
	}
	if strings.HasPrefix(line, "ss://") {
		return parseSS(line)
	}
	if strings.HasPrefix(line, "socks://") || strings.HasPrefix(line, "socks5://") {
		return parseSocks(line)
	}
	if strings.HasPrefix(line, "hy2://") || strings.HasPrefix(line, "hysteria2://") {
		return parseHY2(line)
	}
	return ServerConfig{}, fmt.Errorf("unknown protocol")
}

func parseVLESS(uri string) (ServerConfig, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return ServerConfig{}, err
	}
	name, _ := url.PathUnescape(u.Fragment)
	if name == "" {
		name = "VLESS"
	}

	addr := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}

	id := u.User.Username()
	q := u.Query()

	security := q.Get("security")
	if security == "" {
		security = "tls"
	}
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}

	outbound := map[string]interface{}{
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": addr,
					"port":    port,
					"users": []map[string]interface{}{
						{
							"id":         id,
							"encryption": "none",
							"flow":       q.Get("flow"),
							"level":      8,
						},
					},
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  network,
			"security": security,
		},
		"tag": "proxy",
	}

	stream := outbound["streamSettings"].(map[string]interface{})

	if security == "tls" || security == "reality" {
		tlsSettings := map[string]interface{}{
			"serverName":    q.Get("sni"),
			"allowInsecure": false,
			"show":          false,
		}
		if fp := q.Get("fp"); fp != "" {
			tlsSettings["fingerprint"] = fp
		}
		if security == "reality" {
			tlsSettings["publicKey"] = q.Get("pbk")
			tlsSettings["shortId"] = q.Get("sid")
			tlsSettings["spiderX"] = q.Get("spx")
		}
		stream["tlsSettings"] = tlsSettings
		if security == "reality" {
			stream["realitySettings"] = tlsSettings
			delete(stream, "tlsSettings")
		}
	}

	if network == "ws" {
		wsSettings := map[string]interface{}{
			"path": q.Get("path"),
		}
		if host := q.Get("host"); host != "" {
			wsSettings["headers"] = map[string]string{"Host": host}
		}
		stream["wsSettings"] = wsSettings
	}

	if network == "tcp" {
		stream["tcpSettings"] = map[string]interface{}{
			"header": map[string]interface{}{"type": "none"},
		}
	}

	if q.Get("mux") == "true" {
		outbound["mux"] = map[string]interface{}{"enabled": true, "concurrency": 8}
	}

	return ServerConfig{
		Tag:      "vless-" + hashString(uri),
		Name:     name,
		Address:  addr,
		Port:     port,
		Protocol: "vless",
		Outbound: outbound,
	}, nil
}

func parseVMess(uri string) (ServerConfig, error) {
	b64 := strings.TrimPrefix(uri, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ServerConfig{}, err
	}
	var vm map[string]interface{}
	if err := json.Unmarshal(decoded, &vm); err != nil {
		return ServerConfig{}, err
	}

	addr := getString(vm, "add")
	port := getInt(vm, "port")
	id := getString(vm, "id")
	aid := getInt(vm, "aid")
	ps := getString(vm, "ps")
	if ps == "" {
		ps = "VMess"
	}
	net := getString(vm, "net")
	if net == "" {
		net = "tcp"
	}
	tls := getString(vm, "tls")

	outbound := map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": addr,
					"port":    port,
					"users": []map[string]interface{}{
						{
							"id":       id,
							"alterId":  aid,
							"security": "auto",
							"level":    8,
						},
					},
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  net,
			"security": tls,
		},
		"tag": "proxy",
	}

	if tls == "tls" {
		outbound["streamSettings"].(map[string]interface{})["tlsSettings"] = map[string]interface{}{
			"serverName": getString(vm, "sni"),
		}
	}
	if net == "ws" {
		outbound["streamSettings"].(map[string]interface{})["wsSettings"] = map[string]interface{}{
			"path": getString(vm, "path"),
			"headers": map[string]string{
				"Host": getString(vm, "host"),
			},
		}
	}

	return ServerConfig{
		Tag:      "vmess-" + hashString(uri),
		Name:     ps,
		Address:  addr,
		Port:     port,
		Protocol: "vmess",
		Outbound: outbound,
	}, nil
}

func parseTrojan(uri string) (ServerConfig, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return ServerConfig{}, err
	}
	name, _ := url.PathUnescape(u.Fragment)
	if name == "" {
		name = "Trojan"
	}
	addr := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	pass := u.User.Username()
	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = addr
	}

	outbound := map[string]interface{}{
		"protocol": "trojan",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  addr,
					"port":     port,
					"password": pass,
					"level":    8,
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "tcp",
			"security": "tls",
			"tlsSettings": map[string]interface{}{
				"serverName":    sni,
				"allowInsecure": false,
			},
		},
		"tag": "proxy",
	}

	return ServerConfig{
		Tag:      "trojan-" + hashString(uri),
		Name:     name,
		Address:  addr,
		Port:     port,
		Protocol: "trojan",
		Outbound: outbound,
	}, nil
}

func parseSS(uri string) (ServerConfig, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return ServerConfig{}, err
	}
	name, _ := url.PathUnescape(u.Fragment)
	if name == "" {
		name = "Shadowsocks"
	}
	addr := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 8388
	}

	userStr := u.User.String()
	var method, password string
	if decoded, err := base64.StdEncoding.DecodeString(userStr); err == nil {
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) == 2 {
			method, password = parts[0], parts[1]
		}
	} else {
		parts := strings.SplitN(userStr, ":", 2)
		if len(parts) == 2 {
			method, password = parts[0], parts[1]
		}
	}

	outbound := map[string]interface{}{
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  addr,
					"port":     port,
					"method":   method,
					"password": password,
					"level":    8,
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network": "tcp",
		},
		"tag": "proxy",
	}

	return ServerConfig{
		Tag:      "ss-" + hashString(uri),
		Name:     name,
		Address:  addr,
		Port:     port,
		Protocol: "shadowsocks",
		Outbound: outbound,
	}, nil
}

func parseSocks(uri string) (ServerConfig, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return ServerConfig{}, err
	}
	name, _ := url.PathUnescape(u.Fragment)
	if name == "" {
		name = "SOCKS"
	}
	addr := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 1080
	}
	user := u.User.Username()
	pass, _ := u.User.Password()

	servers := []map[string]interface{}{
		{"address": addr, "port": port, "level": 8},
	}
	if user != "" {
		servers[0]["users"] = []map[string]string{{"user": user, "pass": pass}}
	}

	outbound := map[string]interface{}{
		"protocol": "socks",
		"settings": map[string]interface{}{"servers": servers},
		"tag":      "proxy",
	}

	return ServerConfig{
		Tag:      "socks-" + hashString(uri),
		Name:     name,
		Address:  addr,
		Port:     port,
		Protocol: "socks",
		Outbound: outbound,
	}, nil
}

func parseHY2(uri string) (ServerConfig, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return ServerConfig{}, err
	}
	name, _ := url.PathUnescape(u.Fragment)
	if name == "" {
		name = "Hysteria2"
	}
	addr := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	pass := u.User.Username()

	outbound := map[string]interface{}{
		"protocol": "hysteria",
		"settings": map[string]interface{}{
			"address": addr,
			"port":    port,
			"version": 2,
		},
		"streamSettings": map[string]interface{}{
			"network":  "hysteria",
			"security": "tls",
			"tlsSettings": map[string]interface{}{
				"serverName":    addr,
				"allowInsecure": false,
				"alpn":          []string{"h3"},
			},
			"hysteriaSettings": map[string]interface{}{
				"auth":    pass,
				"version": 2,
			},
		},
		"tag": "proxy",
	}

	return ServerConfig{
		Tag:      "hy2-" + hashString(uri),
		Name:     name,
		Address:  addr,
		Port:     port,
		Protocol: "hysteria2",
		Outbound: outbound,
	}, nil
}

func extractAddrPort(outbound map[string]interface{}) (string, int) {
	settings, _ := outbound["settings"].(map[string]interface{})
	if vnextRaw, ok := settings["vnext"].([]interface{}); ok && len(vnextRaw) > 0 {
		v := vnextRaw[0].(map[string]interface{})
		addr, _ := v["address"].(string)
		port, _ := v["port"].(float64)
		return addr, int(port)
	}
	if serversRaw, ok := settings["servers"].([]interface{}); ok && len(serversRaw) > 0 {
		s := serversRaw[0].(map[string]interface{})
		addr, _ := s["address"].(string)
		port, _ := s["port"].(float64)
		return addr, int(port)
	}
	if addr, ok := settings["address"].(string); ok {
		port, _ := settings["port"].(float64)
		return addr, int(port)
	}
	return "", 0
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		if n, ok := v.(float64); ok {
			return strconv.Itoa(int(n))
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	s := getString(m, key)
	v, _ := strconv.Atoi(s)
	return v
}

func hashString(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
