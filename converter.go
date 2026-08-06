package main

import (
	"encoding/base64"
	"net"
	"net/url"
	"strconv"
)

// ToSingboxOutbound converts an xray-format outbound (from happ subscription)
// into a sing-box native outbound that awg-manager can consume.
// Returns nil if the protocol is unsupported by awg-manager.
func ToSingboxOutbound(xrayOb map[string]interface{}, tag string) map[string]interface{} {
	proto := getString(xrayOb, "protocol")
	if proto == "" {
		return nil
	}

	switch proto {
	case "vless":
		return convertVLESS(xrayOb, tag)
	case "trojan":
		return convertTrojan(xrayOb, tag)
	case "shadowsocks":
		return convertShadowsocks(xrayOb, tag)
	case "hysteria":
		return convertHysteria(xrayOb, tag)
	default:
		return nil
	}
}

// convertVLESS: xray vless → sing-box vless
func convertVLESS(xrayOb map[string]interface{}, tag string) map[string]interface{} {
	settings, _ := xrayOb["settings"].(map[string]interface{})
	vnextRaw, _ := settings["vnext"].([]interface{})
	if len(vnextRaw) == 0 {
		return nil
	}
	vnext := vnextRaw[0].(map[string]interface{})
	addr := getString(vnext, "address")
	port := getInt(vnext, "port")

	usersRaw, _ := vnext["users"].([]interface{})
	if len(usersRaw) == 0 {
		return nil
	}
	user := usersRaw[0].(map[string]interface{})
	uuid := getString(user, "id")
	flow := getString(user, "flow")

	if addr == "" || port == 0 || uuid == "" {
		return nil
	}

	out := map[string]interface{}{
		"type":        "vless",
		"tag":         tag,
		"server":      addr,
		"server_port": port,
		"uuid":        uuid,
	}
	if flow != "" {
		out["flow"] = flow
	}

	stream, _ := xrayOb["streamSettings"].(map[string]interface{})
	if stream != nil {
		network := getString(stream, "network")
		if network == "" {
			network = "tcp"
		}
		transport := map[string]interface{}{"type": network}
		switch network {
		case "ws":
			if ws, ok := stream["wsSettings"].(map[string]interface{}); ok {
				if p := getString(ws, "path"); p != "" {
					transport["path"] = p
				}
				if h, ok := ws["headers"].(map[string]interface{}); ok {
					hdrs := map[string]string{}
					for k, v := range h {
						if s, ok := v.(string); ok {
							hdrs[k] = s
						}
					}
					if len(hdrs) > 0 {
						transport["headers"] = hdrs
					}
				}
			}
		case "grpc":
			if gs, ok := stream["grpcSettings"].(map[string]interface{}); ok {
				if s := getString(gs, "serviceName"); s != "" {
					transport["service_name"] = s
				}
			}
		}
		if network != "tcp" || len(transport) > 1 {
			out["transport"] = transport
		}

		security := getString(stream, "security")
		if security == "tls" || security == "reality" {
			tls := map[string]interface{}{
				"enabled":     true,
				"insecure":    false,
				"server_name": "",
			}
			if ts, ok := stream["tlsSettings"].(map[string]interface{}); ok {
				if sni := getString(ts, "serverName"); sni != "" {
					tls["server_name"] = sni
				}
				if fp := getString(ts, "fingerprint"); fp != "" {
					tls["utls"] = map[string]interface{}{
						"enabled":     true,
						"fingerprint": fp,
					}
				}
			}
			if security == "reality" {
				if rs, ok := stream["realitySettings"].(map[string]interface{}); ok {
					if sni := getString(rs, "serverName"); sni != "" {
						tls["server_name"] = sni
					}
					reality := map[string]interface{}{
						"enabled": true,
					}
					if pk := getString(rs, "publicKey"); pk != "" {
						reality["public_key"] = pk
					}
					if sid := getString(rs, "shortId"); sid != "" {
						reality["short_id"] = sid
					}
					tls["reality"] = reality
					if fp := getString(rs, "fingerprint"); fp != "" {
						tls["utls"] = map[string]interface{}{
							"enabled":     true,
							"fingerprint": fp,
						}
					}
				}
			}
			out["tls"] = tls
		}
	}

	return out
}

// convertTrojan: xray trojan → sing-box trojan
func convertTrojan(xrayOb map[string]interface{}, tag string) map[string]interface{} {
	settings, _ := xrayOb["settings"].(map[string]interface{})
	serversRaw, _ := settings["servers"].([]interface{})
	if len(serversRaw) == 0 {
		return nil
	}
	srv := serversRaw[0].(map[string]interface{})
	addr := getString(srv, "address")
	port := getInt(srv, "port")
	pass := getString(srv, "password")

	if addr == "" || port == 0 || pass == "" {
		return nil
	}

	out := map[string]interface{}{
		"type":        "trojan",
		"tag":         tag,
		"server":      addr,
		"server_port": port,
		"password":    pass,
	}

	stream, _ := xrayOb["streamSettings"].(map[string]interface{})
	if stream != nil {
		security := getString(stream, "security")
		if security == "tls" {
			tls := map[string]interface{}{
				"enabled":  true,
				"insecure": false,
			}
			if ts, ok := stream["tlsSettings"].(map[string]interface{}); ok {
				if sni := getString(ts, "serverName"); sni != "" {
					tls["server_name"] = sni
				}
			}
			out["tls"] = tls
		}
	}

	return out
}

// convertShadowsocks: xray shadowsocks → sing-box shadowsocks
func convertShadowsocks(xrayOb map[string]interface{}, tag string) map[string]interface{} {
	settings, _ := xrayOb["settings"].(map[string]interface{})
	serversRaw, _ := settings["servers"].([]interface{})
	if len(serversRaw) == 0 {
		return nil
	}
	srv := serversRaw[0].(map[string]interface{})
	addr := getString(srv, "address")
	port := getInt(srv, "port")
	method := getString(srv, "method")
	pass := getString(srv, "password")

	if addr == "" || port == 0 || method == "" || pass == "" {
		return nil
	}

	return map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         tag,
		"server":      addr,
		"server_port": port,
		"method":      method,
		"password":    pass,
	}
}

// convertHysteria: xray hysteria → sing-box hysteria2
func convertHysteria(xrayOb map[string]interface{}, tag string) map[string]interface{} {
	settings, _ := xrayOb["settings"].(map[string]interface{})
	addr := getString(settings, "address")
	port := getInt(settings, "port")

	stream, _ := xrayOb["streamSettings"].(map[string]interface{})
	var pass string
	if hs, ok := stream["hysteriaSettings"].(map[string]interface{}); ok {
		pass = getString(hs, "auth")
	}
	if pass == "" {
		pass = getString(settings, "auth")
	}

	if addr == "" || port == 0 {
		return nil
	}

	out := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         tag,
		"server":      addr,
		"server_port": port,
	}
	if pass != "" {
		out["password"] = pass
	}

	if stream != nil {
		security := getString(stream, "security")
		if security == "tls" {
			tls := map[string]interface{}{
				"enabled":  true,
				"insecure": false,
			}
			if ts, ok := stream["tlsSettings"].(map[string]interface{}); ok {
				if sni := getString(ts, "serverName"); sni != "" {
					tls["server_name"] = sni
				}
				if alpn, ok := ts["alpn"].([]interface{}); ok && len(alpn) > 0 {
					alpnStrs := []string{}
					for _, a := range alpn {
						if s, ok := a.(string); ok {
							alpnStrs = append(alpnStrs, s)
						}
					}
					if len(alpnStrs) > 0 {
						tls["alpn"] = alpnStrs
					}
				}
			}
			out["tls"] = tls
		}
	}

	return out
}

// ToShareLink converts a sing-box outbound back to a share-link URI.
// Supported: vless, trojan, shadowsocks, hysteria2.
func ToShareLink(sb map[string]interface{}) string {
	typ := getString(sb, "type")
	tag := getString(sb, "tag")
	server := getString(sb, "server")
	port := getInt(sb, "server_port")
	if server == "" || port == 0 {
		return ""
	}

	switch typ {
	case "vless":
		return encodeVLESS(sb, server, port, tag)
	case "trojan":
		return encodeTrojan(sb, server, port, tag)
	case "shadowsocks":
		return encodeSS(sb, server, port, tag)
	case "hysteria2":
		return encodeHY2(sb, server, port, tag)
	}
	return ""
}

func encodeVLESS(sb map[string]interface{}, server string, port int, tag string) string {
	uuid := getString(sb, "uuid")
	if uuid == "" {
		return ""
	}
	u := url.URL{
		Scheme: "vless",
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
		User:   url.User(uuid),
	}
	q := u.Query()

	if flow := getString(sb, "flow"); flow != "" {
		q.Set("flow", flow)
	}

	if t, ok := sb["transport"].(map[string]interface{}); ok {
		q.Set("type", getString(t, "type"))
		if p := getString(t, "path"); p != "" {
			q.Set("path", p)
		}
		if h, ok := t["headers"].(map[string]interface{}); ok {
			if host := getString(h, "Host"); host != "" {
				q.Set("host", host)
			}
		}
		if sn := getString(t, "service_name"); sn != "" {
			q.Set("serviceName", sn)
		}
	}

	if tls, ok := sb["tls"].(map[string]interface{}); ok {
		if getBool(tls, "enabled") {
			if r, ok := tls["reality"].(map[string]interface{}); ok && getBool(r, "enabled") {
				q.Set("security", "reality")
				if sn := getString(tls, "server_name"); sn != "" {
					q.Set("sni", sn)
				}
				if pk := getString(r, "public_key"); pk != "" {
					q.Set("pbk", pk)
				}
				if sid := getString(r, "short_id"); sid != "" {
					q.Set("sid", sid)
				}
				if utls, ok := tls["utls"].(map[string]interface{}); ok {
					if fp := getString(utls, "fingerprint"); fp != "" {
						q.Set("fp", fp)
					}
				}
			} else {
				q.Set("security", "tls")
				if sn := getString(tls, "server_name"); sn != "" {
					q.Set("sni", sn)
				}
				if utls, ok := tls["utls"].(map[string]interface{}); ok {
					if fp := getString(utls, "fingerprint"); fp != "" {
						q.Set("fp", fp)
					}
				}
			}
		}
	}

	u.RawQuery = q.Encode()
	u.Fragment = tag
	return u.String()
}

func encodeTrojan(sb map[string]interface{}, server string, port int, tag string) string {
	pass := getString(sb, "password")
	if pass == "" {
		return ""
	}
	u := url.URL{
		Scheme: "trojan",
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
		User:   url.User(pass),
	}
	q := u.Query()
	if tls, ok := sb["tls"].(map[string]interface{}); ok && getBool(tls, "enabled") {
		if sn := getString(tls, "server_name"); sn != "" {
			q.Set("sni", sn)
		}
	}
	u.RawQuery = q.Encode()
	u.Fragment = tag
	return u.String()
}

func encodeSS(sb map[string]interface{}, server string, port int, tag string) string {
	method := getString(sb, "method")
	pass := getString(sb, "password")
	if method == "" || pass == "" {
		return ""
	}
	cred := method + ":" + pass
	b64 := base64.StdEncoding.EncodeToString([]byte(cred))
	u := url.URL{
		Scheme: "ss",
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
	}
	u.User = url.User(b64)
	u.Fragment = tag
	return u.String()
}

func encodeHY2(sb map[string]interface{}, server string, port int, tag string) string {
	pass := getString(sb, "password")
	u := url.URL{
		Scheme: "hysteria2",
		Host:   net.JoinHostPort(server, strconv.Itoa(port)),
	}
	if pass != "" {
		u.User = url.User(pass)
	}
	q := u.Query()
	if tls, ok := sb["tls"].(map[string]interface{}); ok && getBool(tls, "enabled") {
		if sn := getString(tls, "server_name"); sn != "" {
			q.Set("sni", sn)
		}
		if alpn, ok := tls["alpn"].([]interface{}); ok && len(alpn) > 0 {
			if s, ok := alpn[0].(string); ok {
				q.Set("alpn", s)
			}
		}
	}
	u.RawQuery = q.Encode()
	u.Fragment = tag
	return u.String()
}

// getBool extracts a boolean from map (handles float64 from JSON).
func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
