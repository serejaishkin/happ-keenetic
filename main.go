package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	listenAddr      = ":3333"
	workDir         = "/opt/etc/happ-keenetic/"
	indexFilePath   = workDir + "happ-index.html"
	subLinksPath    = workDir + "sub_links.json"
	settingsPath    = workDir + "settings.json"
	groupMetaPath   = workDir + "server_groups.json"
	selectorTag     = "proxy-selector"
	singboxSelector = "selector"
	xrayBinPath     = "/opt/sbin/xray"
	xrayConfigPath  = "/opt/etc/xray/config.json"
	xrayLogPath     = "/opt/var/log/xray/error.log"
	singboxBinPath  = "/opt/sbin/sing-box"
	singboxConfig   = "/opt/etc/sing-box/config.json"
	singboxLogPath  = "/opt/var/log/sing-box.log"
	pingTimeout     = 1 * time.Second
)

var configMutex sync.Mutex
var connMu sync.Mutex
var connectedAt time.Time
var nonAlnumRe = regexp.MustCompile(`[^\p{L}\p{N}]+`)

type AppSettings struct {
	SocksPort int    `json:"socks_port"`
	HttpPort  int    `json:"http_port"`
	CronCheck bool   `json:"cron_check"`
	Engine    string `json:"engine"` // "xray" | "sing-box"
}

type SubLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type selectServerRequest struct {
	Tag string `json:"tag"`
}

type ServerInfo struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Network  string `json:"network"`
	Security string `json:"security"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Active   bool   `json:"active"`
}

type ServerGroup struct {
	Label   string       `json:"label"`
	Servers []ServerInfo `json:"servers"`
}

func main() {
	if err := os.MkdirAll(workDir, 0755); err != nil {
		log.Fatalf("Ошибка папки %s: %v", workDir, err)
	}
	if isActiveEngineRunning() {
		connMu.Lock()
		connectedAt = time.Now()
		connMu.Unlock()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/sync", handleSync)
	mux.HandleFunc("/api/save-links", handleSaveLinks)
	mux.HandleFunc("/api/select-server", handleSelectServer)
	mux.HandleFunc("/api/logs", handleLogs)
	mux.HandleFunc("/api/ping", handlePing)
	mux.HandleFunc("/api/save-settings", handleSaveSettings)
	mux.HandleFunc("/api/disconnect", handleDisconnect)
	mux.HandleFunc("/api/connect", handleConnect)

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	log.Printf("Панель запущена на %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Сервер упал: %v", err)
	}
}

func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
}

func handlePreflight(w http.ResponseWriter, r *http.Request) bool {
	enableCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	enableCORS(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]interface{}{"ok": false, "error": msg})
}

func loadSettings() AppSettings {
	data, err := os.ReadFile(settingsPath)
	if err == nil {
		var s AppSettings
		if json.Unmarshal(data, &s) == nil {
			if s.Engine == "" {
				s.Engine = "xray"
			}
			return s
		}
	}
	return AppSettings{SocksPort: 10808, HttpPort: 10809, CronCheck: true, Engine: "xray"}
}

func saveSettings(s AppSettings) {
	if s.Engine != "sing-box" {
		s.Engine = "xray"
	}
	data, _ := json.MarshalIndent(s, "", " ")
	_ = os.WriteFile(settingsPath, data, 0644)

	_ = exec.Command("sh", "-c", "sed -i '/api\\/sync/d' /opt/etc/crontab").Run()
	if s.CronCheck {
		cronLine := "0 4 * * * curl -s -X POST http://127.0.0.1" + listenAddr + "/api/sync >/dev/null 2>&1"
		appendCmd := fmt.Sprintf("echo %q >> /opt/etc/crontab", cronLine)
		_ = exec.Command("sh", "-c", appendCmd).Run()
	}
	_ = exec.Command("/opt/etc/init.d/S10cron", "restart").Run()
}

func loadSubLinks() []SubLink {
	data, err := os.ReadFile(subLinksPath)
	if err != nil {
		return []SubLink{}
	}
	var links []SubLink
	if json.Unmarshal(data, &links) == nil && len(links) > 0 {
		return links
	}
	var plain []string
	if json.Unmarshal(data, &plain) == nil {
		result := make([]SubLink, 0, len(plain))
		for i, u := range plain {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			result = append(result, SubLink{Label: fmt.Sprintf("Подписка %d", i+1), URL: u})
		}
		return result
	}
	return []SubLink{}
}

func saveGroupMeta(meta map[string]string) {
	data, _ := json.MarshalIndent(meta, "", " ")
	_ = os.WriteFile(groupMetaPath, data, 0644)
}

func loadGroupMeta() map[string]string {
	data, err := os.ReadFile(groupMetaPath)
	if err != nil {
		return map[string]string{}
	}
	var meta map[string]string
	if json.Unmarshal(data, &meta) != nil {
		return map[string]string{}
	}
	return meta
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(indexFilePath)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Ошибка чтения %s: %v", indexFilePath, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	s := loadSettings()
	groups, active, err := readServerGroups()
	if err != nil {
		groups = []ServerGroup{}
		active = ""
	}
	running := isActiveEngineRunning()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":             true,
		"xray_running":   running,
		"core_running":   running,
		"engine":         s.Engine,
		"sub_links":      loadSubLinks(),
		"groups":         groups,
		"active_server":  active,
		"settings":       s,
		"uptime_seconds": uptimeSeconds(),
	})
}

func handleSaveLinks(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Нужен POST")
		return
	}
	var req []SubLink
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Кривой JSON")
		return
	}
	var clean []SubLink
	for _, l := range req {
		url := strings.TrimSpace(l.URL)
		if url == "" {
			continue
		}
		label := strings.TrimSpace(l.Label)
		if label == "" {
			label = fmt.Sprintf("Подписка %d", len(clean)+1)
		}
		clean = append(clean, SubLink{Label: label, URL: url})
	}
	data, _ := json.MarshalIndent(clean, "", " ")
	_ = os.WriteFile(subLinksPath, data, 0644)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "sub_links": clean})
}

func handleSync(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Нужен POST")
		return
	}
	links := loadSubLinks()
	if len(links) == 0 {
		writeError(w, http.StatusBadRequest, "Список подписок пуст")
		return
	}

	var combinedOutbounds []map[string]interface{}
	for _, link := range links {
		outbounds, err := fetchSubscription(link.URL)
		if err != nil || len(outbounds) == 0 {
			continue
		}
		for _, ob := range outbounds {
			ob["_group_label"] = link.Label
		}
		combinedOutbounds = append(combinedOutbounds, outbounds...)
	}
	if len(combinedOutbounds) == 0 {
		writeError(w, http.StatusBadGateway, "Не удалось получить серверы ни по одной ссылке")
		return
	}

	tags := patchOutbounds(combinedOutbounds)

	if _, prevActive, err := readSelectorServers(); err == nil && prevActive != "" {
		if reordered, ok := moveTagFirst(tags, prevActive); ok {
			tags = reordered
		}
	}

	groupMeta := make(map[string]string, len(combinedOutbounds))
	for _, ob := range combinedOutbounds {
		tag, _ := ob["tag"].(string)
		label, _ := ob["_group_label"].(string)
		if tag != "" {
			groupMeta[tag] = label
		}
	}
	saveGroupMeta(groupMeta)

	configMutex.Lock()
	defer configMutex.Unlock()

	if err := writeXrayConfig(buildXrayConfig(combinedOutbounds, tags)); err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось сохранить xray config: "+err.Error())
		return
	}
	if err := writeSingboxConfig(buildSingboxConfig(combinedOutbounds, tags)); err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось сохранить sing-box config: "+err.Error())
		return
	}
	if err := restartActiveEngine(); err != nil {
		writeError(w, http.StatusInternalServerError, "Конфиг сохранён, но рестарт ядра не удался: "+err.Error())
		return
	}

	active := ""
	if len(tags) > 0 {
		active = tags[0]
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "servers": tags, "active_server": active})
}

func fetchSubscription(urlStr string) ([]map[string]interface{}, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Happ/2.18.3/Windows/2606241603601")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rawConfigs []interface{}
	if err := json.Unmarshal(body, &rawConfigs); err != nil {
		var single map[string]interface{}
		if err := json.Unmarshal(body, &single); err == nil {
			rawConfigs = append(rawConfigs, single)
		} else {
			return nil, err
		}
	}

	var extracted []map[string]interface{}
	for _, confItem := range rawConfigs {
		cfg, ok := confItem.(map[string]interface{})
		if !ok {
			continue
		}
		baseName, _ := cfg["remarks"].(string)
		baseName = strings.ReplaceAll(baseName, " bypass", "")
		baseName = strings.ReplaceAll(baseName, "proxy-", "")
		baseName = strings.ReplaceAll(baseName, "-direct", "")
		baseName = sanitizeName(baseName)

		if rawOutbounds, exists := cfg["outbounds"]; exists {
			if list, ok := rawOutbounds.([]interface{}); ok {
				for _, item := range list {
					if m, ok := item.(map[string]interface{}); ok {
						protocol, _ := m["protocol"].(string)
						if protocol != "freedom" && protocol != "blackhole" && m["tag"] != "ru-upstream" {
							m["_clean_sys_name"] = baseName
							extracted = append(extracted, m)
						}
					}
				}
			}
		}
	}
	return extracted, nil
}

func sanitizeName(s string) string {
	s = nonAlnumRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	if s == "" {
		s = "Node"
	}
	return s
}

func stableServerID(ob map[string]interface{}) string {
	server, _ := ob["server"].(string)
	var portStr string
	switch p := ob["port"].(type) {
	case float64:
		portStr = fmt.Sprintf("%d", int(p))
	case int:
		portStr = fmt.Sprintf("%d", p)
	case string:
		portStr = p
	}
	sum := crc32.ChecksumIEEE([]byte(server + ":" + portStr))
	return fmt.Sprintf("%05d", sum%100000)
}

func patchOutbounds(outbounds []map[string]interface{}) []string {
	tags := make([]string, 0, len(outbounds))
	seen := make(map[string]int)

	for _, ob := range outbounds {
		protocol, _ := ob["protocol"].(string)
		protocol = strings.ToUpper(protocol)
		cleanSysName, _ := ob["_clean_sys_name"].(string)
		if cleanSysName == "" {
			cleanSysName = "Node"
		}

		baseTag := fmt.Sprintf("%s_%s_%s", cleanSysName, protocol, stableServerID(ob))
		finalTag := baseTag
		if n, exists := seen[baseTag]; exists {
			n++
			seen[baseTag] = n
			finalTag = fmt.Sprintf("%s_%d", baseTag, n)
		} else {
			seen[baseTag] = 1
		}

		ob["tag"] = finalTag
		tags = append(tags, finalTag)

		if strings.ToLower(protocol) == "hysteria" {
			ob["protocol"] = "hysteria2"
			if settings, ok := ob["settings"].(map[string]interface{}); ok {
				settings["packet_encoding"] = "xray"
				if auth, exists := settings["auth"]; exists {
					settings["password"] = auth
				}
			}
			stream, ok := ob["streamSettings"].(map[string]interface{})
			if !ok {
				stream = map[string]interface{}{}
				ob["streamSettings"] = stream
			}
			stream["network"] = "udp"
			stream["security"] = "tls"
			tlsSettings := map[string]interface{}{
				"serverName": "sni.nl01-cherry.online",
				"alpn":         []string{"h3"},
				"fingerprint":  "firefox",
			}
			if origTls, ok := stream["tlsSettings"].(map[string]interface{}); ok {
				if sn, exists := origTls["serverName"]; exists && sn != "" {
					tlsSettings["serverName"] = sn
				}
			}
			stream["tlsSettings"] = tlsSettings
		}
	}
	return tags
}

func buildXrayConfig(providerOutbounds []map[string]interface{}, tags []string) map[string]interface{} {
	s := loadSettings()
	inbounds := []map[string]interface{}{
		{
			"tag": "socks-in", "listen": "127.0.0.1", "port": s.SocksPort, "protocol": "socks",
			"settings": map[string]interface{}{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
			"sniffing": map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls"}},
		},
		{
			"tag": "http-in", "listen": "127.0.0.1", "port": s.HttpPort, "protocol": "http",
			"settings": map[string]interface{}{},
		},
	}
	selector := map[string]interface{}{
		"tag": selectorTag, "protocol": "selector",
		"settings": map[string]interface{}{"outbounds": tags, "strategy": "first"},
	}
	direct := map[string]interface{}{"tag": "direct", "protocol": "freedom", "settings": map[string]interface{}{}}
	block := map[string]interface{}{"tag": "block", "protocol": "blackhole", "settings": map[string]interface{}{}}

	outbounds := make([]interface{}, 0, len(providerOutbounds)+3)
	for _, ob := range providerOutbounds {
		t, _ := ob["tag"].(string)
		if t != "direct" && t != "block" && t != selectorTag {
			outbounds = append(outbounds, ob)
		}
	}
	outbounds = append(outbounds, selector, direct, block)

	return map[string]interface{}{
		"log":      map[string]interface{}{"access": "", "error": xrayLogPath, "loglevel": "warning"},
		"inbounds": inbounds, "outbounds": outbounds,
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"rules": []map[string]interface{}{
				{"type": "field", "outboundTag": selectorTag, "network": "tcp,udp"},
			},
		},
	}
}

func buildSingboxConfig(providerOutbounds []map[string]interface{}, tags []string) map[string]interface{} {
	s := loadSettings()
	inbounds := []map[string]interface{}{
		{
			"type": "tun", "tag": "tun-in", "interface_name": "happ-tun",
			"auto_route": true, "strict_route": true, "stack": "system",
			"inet4_address": "172.19.0.1/30",
		},
		{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": s.SocksPort},
		{"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": s.HttpPort},
	}

	outbounds := make([]interface{}, 0, len(providerOutbounds)+3)
	tagList := make([]interface{}, len(tags))
	for i, t := range tags {
		tagList[i] = t
	}
	outbounds = append(outbounds, map[string]interface{}{
		"type": "selector", "tag": singboxSelector, "outbounds": tagList,
	})

	for _, ob := range providerOutbounds {
		outbounds = append(outbounds, convertToSingboxOutbound(ob))
	}
	outbounds = append(outbounds,
		map[string]interface{}{"type": "direct", "tag": "direct"},
		map[string]interface{}{"type": "block", "tag": "block"},
	)

	return map[string]interface{}{
		"log":      map[string]interface{}{"level": "warn", "output": singboxLogPath},
		"inbounds": inbounds,
		"outbounds": outbounds,
		"route": map[string]interface{}{
			"auto_detect_interface": true,
			"final":                 singboxSelector,
		},
	}
}

func convertToSingboxOutbound(ob map[string]interface{}) map[string]interface{} {
	proto, _ := ob["protocol"].(string)
	proto = strings.ToLower(proto)
	tag, _ := ob["tag"].(string)
	server, _ := ob["server"].(string)
	port := outboundPort(ob)

	node := map[string]interface{}{
		"tag": tag, "server": server, "server_port": port,
	}

	switch proto {
	case "hysteria", "hysteria2":
		node["type"] = "hysteria2"
		if settings, ok := ob["settings"].(map[string]interface{}); ok {
			if pw, ok := settings["password"]; ok {
				node["password"] = pw
			}
			if auth, ok := settings["auth"]; ok {
				node["password"] = auth
			}
		}
		tls := map[string]interface{}{"enabled": true, "alpn": []string{"h3"}}
		if ss, ok := ob["streamSettings"].(map[string]interface{}); ok {
			if tlsSettings, ok := ss["tlsSettings"].(map[string]interface{}); ok {
				if sn, ok := tlsSettings["serverName"].(string); ok && sn != "" {
					tls["server_name"] = sn
				}
			}
		}
		node["tls"] = tls

	case "vless":
		node["type"] = "vless"
		if settings, ok := ob["settings"].(map[string]interface{}); ok {
			if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
				if vn, ok := vnext[0].(map[string]interface{}); ok {
					if users, ok := vn["users"].([]interface{}); ok && len(users) > 0 {
						if user, ok := users[0].(map[string]interface{}); ok {
							node["uuid"] = user["id"]
							if flow, ok := user["flow"].(string); ok {
								node["flow"] = flow
							}
						}
					}
				}
			}
		}
		applySingboxStream(node, ob)

	case "vmess":
		node["type"] = "vmess"
		if settings, ok := ob["settings"].(map[string]interface{}); ok {
			if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
				if vn, ok := vnext[0].(map[string]interface{}); ok {
					if users, ok := vn["users"].([]interface{}); ok && len(users) > 0 {
						if user, ok := users[0].(map[string]interface{}); ok {
							node["uuid"] = user["id"]
							if aid, ok := user["alterId"]; ok {
								node["alter_id"] = aid
							}
						}
					}
				}
			}
		}
		applySingboxStream(node, ob)

	default:
		node["type"] = proto
	}
	return node
}

func applySingboxStream(node map[string]interface{}, ob map[string]interface{}) {
	ss, ok := ob["streamSettings"].(map[string]interface{})
	if !ok {
		return
	}
	if network, ok := ss["network"].(string); ok {
		node["network"] = network
	}
	security, _ := ss["security"].(string)
	switch security {
	case "reality":
		if rs, ok := ss["realitySettings"].(map[string]interface{}); ok {
			node["tls"] = map[string]interface{}{
				"enabled":     true,
				"server_name": rs["serverName"],
				"reality": map[string]interface{}{
					"enabled":    true,
					"public_key": rs["publicKey"],
					"short_id":   rs["shortId"],
				},
			}
		}
	case "tls":
		tls := map[string]interface{}{"enabled": true}
		if tlsSettings, ok := ss["tlsSettings"].(map[string]interface{}); ok {
			if sn, ok := tlsSettings["serverName"].(string); ok {
				tls["server_name"] = sn
			}
			if alpn, ok := tlsSettings["alpn"].([]interface{}); ok {
				tls["alpn"] = alpn
			}
		}
		node["tls"] = tls
	}
}

func outboundPort(ob map[string]interface{}) int {
	switch p := ob["port"].(type) {
	case float64:
		return int(p)
	case int:
		return p
	case string:
		var port int
		fmt.Sscanf(p, "%d", &port)
		return port
	}
	return 0
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	s := loadSettings()
	path := activeConfigPath(s.Engine)

	configMutex.Lock()
	data, err := os.ReadFile(path)
	configMutex.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Нет конфига")
		return
	}

	var cfg map[string]interface{}
	_ = json.Unmarshal(data, &cfg)
	outbounds, _ := cfg["outbounds"].([]interface{})

	results := make(map[string]interface{})
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, obRaw := range outbounds {
		ob, ok := obRaw.(map[string]interface{})
		if !ok {
			continue
		}
		tag, server, port := outboundEndpoint(ob, s.Engine)
		if tag == "" || server == "" || port == 0 {
			continue
		}
		if tag == selectorTag || tag == singboxSelector || tag == "direct" || tag == "block" {
			continue
		}

		wg.Add(1)
		go func(t, srv string, p int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", srv, p)
			start := time.Now()
			conn, err := net.DialTimeout("tcp", addr, pingTimeout)
			if err != nil {
				mu.Lock()
				results[t] = "timeout"
				mu.Unlock()
				return
			}
			conn.Close()
			elapsed := time.Since(start).Milliseconds()
			mu.Lock()
			results[t] = fmt.Sprintf("%d ms", elapsed)
			mu.Unlock()
		}(tag, server, port)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "ping": results})
}

func outboundEndpoint(ob map[string]interface{}, engine string) (tag, server string, port int) {
	tag, _ = ob["tag"].(string)
	if engine == "sing-box" {
		server, _ = ob["server"].(string)
		switch p := ob["server_port"].(type) {
		case float64:
			port = int(p)
		case int:
			port = p
		}
		return
	}
	server, _ = ob["server"].(string)
	port = outboundPort(ob)
	return
}

func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Нужен POST")
		return
	}
	var incoming AppSettings
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		writeError(w, http.StatusBadRequest, "Кривые настройки")
		return
	}
	if incoming.SocksPort <= 0 || incoming.SocksPort > 65535 || incoming.HttpPort <= 0 || incoming.HttpPort > 65535 {
		writeError(w, http.StatusBadRequest, "Порты должны быть в диапазоне 1-65535")
		return
	}
	prev := loadSettings()
	saveSettings(incoming)

	engineChanged := prev.Engine != incoming.Engine
	configMutex.Lock()
	var err error
	if engineChanged {
		err = restartActiveEngine()
	} else if isActiveEngineRunning() {
		err = restartActiveEngine()
	}
	configMutex.Unlock()

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Настройки сохранены, но перезапуск ядра не удался: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func handleSelectServer(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Нужен POST")
		return
	}
	var req selectServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Кривой JSON")
		return
	}

	s := loadSettings()
	configMutex.Lock()
	defer configMutex.Unlock()

	path := activeConfigPath(s.Engine)
	data, err := os.ReadFile(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Ошибка чтения конфига")
		return
	}
	var cfg map[string]interface{}
	_ = json.Unmarshal(data, &cfg)
	outboundsRaw, _ := cfg["outbounds"].([]interface{})

	found := false
	for _, obRaw := range outboundsRaw {
		ob, ok := obRaw.(map[string]interface{})
		if !ok {
			continue
		}
		tag, _ := ob["tag"].(string)
		if tag != selectorTag && tag != singboxSelector {
			continue
		}

		var current []string
		if s.Engine == "sing-box" {
			tagsRaw, _ := ob["outbounds"].([]interface{})
			for _, t := range tagsRaw {
				if str, ok := t.(string); ok {
					current = append(current, str)
				}
			}
			reordered, ok := moveTagFirst(current, req.Tag)
			if !ok {
				writeError(w, http.StatusNotFound, "Сервер не найден")
				return
			}
			newTags := make([]interface{}, len(reordered))
			for i, str := range reordered {
				newTags[i] = str
			}
			ob["outbounds"] = newTags
		} else {
			settings, _ := ob["settings"].(map[string]interface{})
			tagsRaw, _ := settings["outbounds"].([]interface{})
			for _, t := range tagsRaw {
				if str, ok := t.(string); ok {
					current = append(current, str)
				}
			}
			reordered, ok := moveTagFirst(current, req.Tag)
			if !ok {
				writeError(w, http.StatusNotFound, "Сервер не найден")
				return
			}
			newTags := make([]interface{}, len(reordered))
			for i, str := range reordered {
				newTags[i] = str
			}
			settings["outbounds"] = newTags
		}
		found = true
		break
	}
	if !found {
		writeError(w, http.StatusInternalServerError, "Селектор не найден")
		return
	}

	newData, _ := json.MarshalIndent(cfg, "", " ")
	_ = os.WriteFile(path, newData, 0644)

	// Синхронизируем выбор в обоих конфигах, чтобы переключение движка не сбрасывало сервер.
	if s.Engine == "sing-box" {
		syncSelectorInConfig(xrayConfigPath, req.Tag, false)
	} else {
		syncSelectorInConfig(singboxConfig, req.Tag, true)
	}

	if isActiveEngineRunning() {
		_ = restartActiveEngine()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "active_server": req.Tag})
}

func syncSelectorInConfig(path, chosenTag string, targetIsSingbox bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cfg map[string]interface{}
	if json.Unmarshal(data, &cfg) != nil {
		return
	}
	outboundsRaw, _ := cfg["outbounds"].([]interface{})
	for _, obRaw := range outboundsRaw {
		ob, ok := obRaw.(map[string]interface{})
		if !ok {
			continue
		}
		tag, _ := ob["tag"].(string)
		wantTag := selectorTag
		if targetIsSingbox {
			wantTag = singboxSelector
		}
		if tag != wantTag {
			continue
		}

		var current []string
		if targetIsSingbox {
			tagsRaw, _ := ob["outbounds"].([]interface{})
			for _, t := range tagsRaw {
				if str, ok := t.(string); ok {
					current = append(current, str)
				}
			}
			reordered, ok := moveTagFirst(current, chosenTag)
			if !ok {
				return
			}
			newTags := make([]interface{}, len(reordered))
			for i, str := range reordered {
				newTags[i] = str
			}
			ob["outbounds"] = newTags
		} else {
			settings, _ := ob["settings"].(map[string]interface{})
			tagsRaw, _ := settings["outbounds"].([]interface{})
			for _, t := range tagsRaw {
				if str, ok := t.(string); ok {
					current = append(current, str)
				}
			}
			reordered, ok := moveTagFirst(current, chosenTag)
			if !ok {
				return
			}
			newTags := make([]interface{}, len(reordered))
			for i, str := range reordered {
				newTags[i] = str
			}
			settings["outbounds"] = newTags
		}
		break
	}
	newData, _ := json.MarshalIndent(cfg, "", " ")
	_ = os.WriteFile(path, newData, 0644)
}

func handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Нужен POST")
		return
	}
	stopAllEngines()
	connMu.Lock()
	connectedAt = time.Time{}
	connMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Нужен POST")
		return
	}
	s := loadSettings()
	if _, err := os.Stat(activeConfigPath(s.Engine)); err != nil {
		writeError(w, http.StatusBadRequest, "Конфиг ещё не создан — сначала SYNC SERVERS")
		return
	}
	configMutex.Lock()
	err := restartActiveEngine()
	configMutex.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Не удалось запустить ядро: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	s := loadSettings()
	path := xrayLogPath
	if s.Engine == "sing-box" {
		path = singboxLogPath
	}
	file, err := os.Open(path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "logs": []string{"Лог пуст."}})
		return
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	start := 0
	if len(lines) > 25 {
		start = len(lines) - 25
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "logs": lines[start:]})
}

func activeConfigPath(engine string) string {
	if engine == "sing-box" {
		return singboxConfig
	}
	return xrayConfigPath
}

func writeXrayConfig(cfg map[string]interface{}) error {
	if err := os.MkdirAll(filepath.Dir(xrayConfigPath), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(xrayConfigPath, data, 0644)
}

func writeSingboxConfig(cfg map[string]interface{}) error {
	if err := os.MkdirAll(filepath.Dir(singboxConfig), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(singboxConfig, data, 0644)
}

func isProcessRunning(name string) bool {
	out, err := exec.Command("pidof", name).Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}

func isActiveEngineRunning() bool {
	s := loadSettings()
	if s.Engine == "sing-box" {
		return isProcessRunning("sing-box")
	}
	return isProcessRunning("xray")
}

func readSelectorServers() ([]string, string, error) {
	s := loadSettings()
	path := activeConfigPath(s.Engine)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, "", err
	}
	outboundsRaw, ok := cfg["outbounds"].([]interface{})
	if !ok {
		return nil, "", fmt.Errorf("outbounds отсутствуют")
	}
	for _, obRaw := range outboundsRaw {
		ob, ok := obRaw.(map[string]interface{})
		if !ok {
			continue
		}
		tag, _ := ob["tag"].(string)
		if tag != selectorTag && tag != singboxSelector {
			continue
		}
		var tags []string
		if s.Engine == "sing-box" {
			tagsRaw, _ := ob["outbounds"].([]interface{})
			for _, t := range tagsRaw {
				if str, ok := t.(string); ok {
					tags = append(tags, str)
				}
			}
		} else {
			settings, ok := ob["settings"].(map[string]interface{})
			if !ok {
				return nil, "", fmt.Errorf("у селектора нет settings")
			}
			tagsRaw, ok := settings["outbounds"].([]interface{})
			if !ok {
				return nil, "", fmt.Errorf("у селектора нет settings.outbounds")
			}
			for _, t := range tagsRaw {
				if str, ok := t.(string); ok {
					tags = append(tags, str)
				}
			}
		}
		active := ""
		if len(tags) > 0 {
			active = tags[0]
		}
		return tags, active, nil
	}
	return nil, "", fmt.Errorf("селектор не найден")
}

func readServerGroups() ([]ServerGroup, string, error) {
	s := loadSettings()
	path := activeConfigPath(s.Engine)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, "", err
	}
	outboundsRaw, ok := cfg["outbounds"].([]interface{})
	if !ok {
		return nil, "", fmt.Errorf("outbounds отсутствуют")
	}

	active := ""
	for _, obRaw := range outboundsRaw {
		ob, ok := obRaw.(map[string]interface{})
		if !ok {
			continue
		}
		tag, _ := ob["tag"].(string)
		if tag != selectorTag && tag != singboxSelector {
			continue
		}
		if s.Engine == "sing-box" {
			tagsRaw, _ := ob["outbounds"].([]interface{})
			if len(tagsRaw) > 0 {
				active, _ = tagsRaw[0].(string)
			}
		} else {
			settings, _ := ob["settings"].(map[string]interface{})
			tagsRaw, _ := settings["outbounds"].([]interface{})
			if len(tagsRaw) > 0 {
				active, _ = tagsRaw[0].(string)
			}
		}
	}

	groupMeta := loadGroupMeta()
	groupOrder := make([]string, 0)
	groupsMap := make(map[string]*ServerGroup)

	for _, obRaw := range outboundsRaw {
		ob, ok := obRaw.(map[string]interface{})
		if !ok {
			continue
		}
		tag, server, port := outboundEndpoint(ob, s.Engine)
		if tag == "" || tag == selectorTag || tag == singboxSelector || tag == "direct" || tag == "block" {
			continue
		}

		var protocol, network, security string
		if s.Engine == "sing-box" {
			protocol, _ = ob["type"].(string)
		} else {
			protocol, _ = ob["protocol"].(string)
			if ss, ok := ob["streamSettings"].(map[string]interface{}); ok {
				network, _ = ss["network"].(string)
				security, _ = ss["security"].(string)
			}
		}

		label := groupMeta[tag]
		if label == "" {
			label, _ = ob["_group_label"].(string)
		}
		if label == "" {
			label = "Без группы"
		}

		g, exists := groupsMap[label]
		if !exists {
			g = &ServerGroup{Label: label}
			groupsMap[label] = g
			groupOrder = append(groupOrder, label)
		}
		g.Servers = append(g.Servers, ServerInfo{
			Tag: tag, Protocol: protocol, Network: network, Security: security,
			Server: server, Port: port, Active: tag == active,
		})
	}

	result := make([]ServerGroup, 0, len(groupOrder))
	for _, label := range groupOrder {
		result = append(result, *groupsMap[label])
	}
	return result, active, nil
}

func moveTagFirst(tags []string, chosen string) ([]string, bool) {
	present := false
	for _, t := range tags {
		if t == chosen {
			present = true
			break
		}
	}
	if !present {
		return nil, false
	}
	result := make([]string, 0, len(tags))
	result = append(result, chosen)
	for _, t := range tags {
		if t != chosen {
			result = append(result, t)
		}
	}
	return result, true
}

func stopAllEngines() {
	_ = exec.Command("killall", "xray").Run()
	_ = exec.Command("killall", "sing-box").Run()
	time.Sleep(400 * time.Millisecond)
}

func restartActiveEngine() error {
	stopAllEngines()
	s := loadSettings()

	if s.Engine == "sing-box" {
		cmd := exec.Command(singboxBinPath, "run", "-c", singboxConfig)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return err
		}
	} else {
		cmd := exec.Command(xrayBinPath, "run", "-c", xrayConfigPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return err
		}
		_ = exec.Command("ndm", "-c", fmt.Sprintf("opkg proxy upstream vless socks 127.0.0.1:%d", s.SocksPort)).Run()
		_ = exec.Command("ndm", "-c", "system configuration save").Run()
	}

	connMu.Lock()
	connectedAt = time.Now()
	connMu.Unlock()
	return nil
}

func uptimeSeconds() int64 {
	connMu.Lock()
	base := connectedAt
	connMu.Unlock()
	if base.IsZero() || !isActiveEngineRunning() {
		return 0
	}
	return int64(time.Since(base).Seconds())
}