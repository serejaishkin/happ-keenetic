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
	HttpPort  int    `json:"http_port"` // 🌟 Выровнен заглавный регистр
	CronCheck bool   `json:"cron_check"`
	Engine    string `json:"engine"`
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

func loadSettings() AppSettings {
	data, err := os.ReadFile(settingsPath)
	if err == nil {
		var s AppSettings
		if json.Unmarshal(data, &s) == nil {
			if s.Engine == "" { s.Engine = "xray" }
			return s
		}
	}
	return AppSettings{SocksPort: 10808, HttpPort: 10809, CronCheck: true, Engine: "xray"}
}

func saveSettings(s AppSettings) {
	if s.Engine != "sing-box" { s.Engine = "xray" }
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
	if err != nil { return []SubLink{} }
	var links []SubLink
	if json.Unmarshal(data, &links) == nil && len(links) > 0 { return links }
	var plain []string
	if json.Unmarshal(data, &plain) == nil {
		result := make([]SubLink, 0, len(plain))
		for i, u := range plain {
			u = strings.TrimSpace(u)
			if u == "" { continue }
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
	if err != nil { return map[string]string{} }
	var meta map[string]string
	if json.Unmarshal(data, &meta) != nil { return map[string]string{} }
	return meta
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

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) { return }
	if r.URL.Path != "/" { http.NotFound(w, r); return }
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
	if handlePreflight(w, r) { return }
	s := loadSettings()
	groups, active, err := readServerGroups()
	if err != nil { groups = []ServerGroup{}; active = "" }
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
	if handlePreflight(w, r) { return }
	if r.Method != http.MethodPost { writeError(w, http.StatusMethodNotAllowed, "Нужен POST"); return }
	var req []SubLink
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Кривой JSON")
		return
	}
	var clean []SubLink
	for _, l := range req {
		url := strings.TrimSpace(l.URL)
		if url == "" { continue }
		label := strings.TrimSpace(l.Label)
		if label == "" { label = fmt.Sprintf("Подписка %d", len(clean)+1) }
		clean = append(clean, SubLink{Label: label, URL: url})
	}
	data, _ := json.MarshalIndent(clean, "", " ")
	_ = os.WriteFile(subLinksPath, data, 0644)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "sub_links": clean})
}

func handleSync(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) { return }
	if r.Method != http.MethodPost { writeError(w, http.StatusMethodNotAllowed, "Нужен POST"); return }
	links := loadSubLinks()
	if len(links) == 0 { writeError(w, http.StatusBadRequest, "Список подписок пуст"); return }

	var combinedOutbounds []map[string]interface{}
	groupMeta := make(map[string]string)

	for _, link := range links {
		outbounds, err := fetchSubscription(link.URL)
		if err != nil || len(outbounds) == 0 { continue }
		for _, ob := range outbounds { ob["_group_label"] = link.Label }
		combinedOutbounds = append(combinedOutbounds, outbounds...)
	}
	if len(combinedOutbounds) == 0 { writeError(w, http.StatusBadGateway, "Не удалось получить серверы"); return }

	tags := patchOutbounds(combinedOutbounds)
	for _, ob := range combinedOutbounds {
		if t, ok := ob["tag"].(string); ok {
			if g, exists := ob["_group_label"].(string); exists { groupMeta[t] = g }
		}
	}
	saveGroupMeta(groupMeta)

	s := loadSettings()
	configMutex.Lock()
	defer configMutex.Unlock()

	var targetTag string
	if _, prevActive, err := readSelectorServers(); err == nil && prevActive != "" {
		for _, t := range tags { if t == prevActive { targetTag = prevActive; break } }
	}
	// 🌟 ФИКС СРЕЗА: Безопасно извлекаем первый элемент текстового массива строк
	if targetTag == "" && len(tags) > 0 { targetTag = tags[0] }

	if s.Engine == "sing-box" {
		fullConfig := buildSingboxConfig(combinedOutbounds, tags, targetTag)
		_ = os.MkdirAll(filepath.Dir(singboxConfig), 0755)
		indentData, _ := json.MarshalIndent(fullConfig, "", " ")
		_ = os.WriteFile(singboxConfig, indentData, 0644)
	} else {
		fullConfig := buildXrayConfig(combinedOutbounds, tags, targetTag)
		_ = os.MkdirAll(filepath.Dir(xrayConfigPath), 0755)
		indentData, _ := json.MarshalIndent(fullConfig, "", " ")
		_ = os.WriteFile(xrayConfigPath, indentData, 0644)
	}
	_ = restartActiveEngine()
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "servers": tags, "active_server": targetTag})
}
func fetchSubscription(urlStr string) ([]map[string]interface{}, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", urlStr, nil)
	req.Header.Set("User-Agent", "Happ/2.18.3/Windows/2606241603601")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf("status %d", resp.StatusCode) }
	
	body, err := io.ReadAll(resp.Body)
	if err != nil { return nil, err }

	var rawConfigs []interface{}
	if err := json.Unmarshal(body, &rawConfigs); err != nil {
		var single map[string]interface{}
		if err := json.Unmarshal(body, &single); err == nil {
			rawConfigs = append(rawConfigs, single)
		} else { return nil, err }
	}

	var extracted []map[string]interface{}
	for _, confItem := range rawConfigs {
		cfg, ok := confItem.(map[string]interface{})
		if !ok { continue }
		
		baseName, _ := cfg["remarks"].(string)
		baseName = strings.ReplaceAll(baseName, " bypass", "")
		baseName = strings.ReplaceAll(baseName, "proxy-", "")
		baseName = strings.ReplaceAll(baseName, "-direct", "")
		baseName = nonAlnumRe.ReplaceAllString(baseName, "_")
		if baseName == "" { baseName = "Liberty_Node" }

		if rawOutbounds, exists := cfg["outbounds"]; exists {
			if list, ok := rawOutbounds.([]interface{}); ok {
				for _, item := range list {
					if m, ok := item.(map[string]interface{}); ok {
						protocol, _ := m["protocol"].(string)
						if protocol == "" { protocol, _ = m["type"].(string) }
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

func patchOutbounds(outbounds []map[string]interface{}) []string {
	tags := make([]string, 0, len(outbounds))
	for _, ob := range outbounds {
		protocol, _ := ob["protocol"].(string)
		if protocol == "" { protocol, _ = ob["type"].(string) }
		protocol = strings.ToUpper(protocol)
		cleanSysName, _ := ob["_clean_sys_name"].(string)
		
		server, _ := ob["server"].(string)
		portRaw, _ := ob["port"]
		if portRaw == nil { portRaw = ob["server_port"] }
		var port int
		if pFloat, ok := portRaw.(float64); ok { port = int(pFloat) } else if pInt, ok := portRaw.(int); ok { port = pInt }

		srvHash := crc32.ChecksumIEEE([]byte(fmt.Sprintf("%s:%d", server, port)))
		finalTag := fmt.Sprintf("%s_%s_%X", cleanSysName, protocol, srvHash)
		ob["tag"] = finalTag
		tags = append(tags, finalTag)

		if strings.ToLower(protocol) == "hysteria" || strings.ToLower(protocol) == "hysteria2" {
			ob["protocol"] = "hysteria2"
			if settings, ok := ob["settings"].(map[string]interface{}); ok {
				if auth, exists := settings["auth"]; exists { settings["password"] = auth }
			}
			stream, ok := ob["streamSettings"].(map[string]interface{})
			if !ok { stream = map[string]interface{}{}; ob["streamSettings"] = stream }
			stream["network"] = "udp"
			stream["security"] = "tls"
			
			tlsSettings := map[string]interface{}{
				"serverName": "sni.nl01-cherry.online", "alpn": []string{"h3"}, "fingerprint": "firefox",
			}
			if origTls, ok := stream["tlsSettings"].(map[string]interface{}); ok {
				if sn, exists := origTls["serverName"]; exists && sn != "" { tlsSettings["serverName"] = sn }
			}
			stream["tlsSettings"] = tlsSettings
		}
	}
	return tags
}
func buildXrayConfig(providerOutbounds []map[string]interface{}, tags []string, active string) map[string]interface{} {
	s := loadSettings()
	inbounds := []map[string]interface{}{
		{"tag": "socks-in", "listen": "127.0.0.1", "port": s.SocksPort, "protocol": "socks", "settings": map[string]interface{}{"auth": "noauth", "udp": true, "ip": "127.0.0.1"}, "sniffing": map[string]interface{}{"enabled": true, "destOverride": []string{"http", "tls"}}},
		{"tag": "http-in", "listen": "127.0.0.1", "port": s.HttpPort, "protocol": "http", "settings": map[string]interface{}{}},
	}
	
	reorderedTags := moveTagFirst(tags, active)
	selector := map[string]interface{}{"tag": selectorTag, "protocol": "selector", "settings": map[string]interface{}{"outbounds": reorderedTags, "strategy": "first"}}
	direct := map[string]interface{}{"tag": "direct", "protocol": "freedom", "settings": map[string]interface{}{}}
	block := map[string]interface{}{"tag": "block", "protocol": "blackhole", "settings": map[string]interface{}{}}

	outbounds := make([]interface{}, 0, len(providerOutbounds)+3)
	for _, ob := range providerOutbounds {
		t, _ := ob["tag"].(string)
		if t != "direct" && t != "block" && t != "selector" { outbounds = append(outbounds, ob) }
	}
	outbounds = append(outbounds, selector, direct, block)
	return map[string]interface{}{
		"log": map[string]interface{}{"access": "", "error": xrayLogPath, "loglevel": "warning"},
		"inbounds": inbounds, "outbounds": outbounds,
		"routing": map[string]interface{}{"domainStrategy": "AsIs", "rules": []map[string]interface{}{{"type": "field", "outboundTag": selectorTag, "network": "tcp,udp"}}},
	}
}

func buildSingboxConfig(providerOutbounds []map[string]interface{}, tags []string, active string) map[string]interface{} {
	s := loadSettings()
	inbounds := []map[string]interface{}{
		{ "type": "tun", "tag": "tun-in", "interface_name": "happ-tun", "auto_route": true, "strict_route": true, "stack": "system" },
		{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": s.SocksPort },
		{ "type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": s.HttpPort },
	}
	outbounds := make([]interface{}, 0, len(providerOutbounds)+3)
	
	reorderedTags := moveTagFirst(tags, active)
	selector := map[string]interface{}{ "type": "selector", "tag": singboxSelector, "outbounds": reorderedTags }
	direct := map[string]interface{}{ "type": "direct", "tag": "direct" }
	block := map[string]interface{}{ "type": "block", "tag": "block" }

	outbounds = append(outbounds, selector)
	for _, ob := range providerOutbounds {
		proto, _ := ob["protocol"].(string)
		if proto == "" { proto, _ = ob["type"].(string) }
		tag, _ := ob["tag"].(string)
		server, _ := ob["server"].(string)
		
		portRaw, _ := ob["port"]
		if portRaw == nil { portRaw = ob["server_port"] }
		var port int
		if pFloat, ok := portRaw.(float64); ok { port = int(pFloat) } else if pInt, ok := portRaw.(int); ok { port = pInt }
		
		node := map[string]interface{}{ "type": strings.ToLower(proto), "tag": tag, "server": server, "server_port": port }
		if strings.ToLower(proto) == "hysteria2" || strings.ToLower(proto) == "hysteria" {
			node["type"] = "hysteria2"
			if settings, ok := ob["settings"].(map[string]interface{}); ok { node["password"] = settings["password"] }
			node["tls"] = map[string]interface{}{"enabled": true, "alpn": []string{"h3"}}
		}
		outbounds = append(outbounds, node)
	}
	outbounds = append(outbounds, direct, block)
	return map[string]interface{}{
		"log": map[string]interface{}{"level": "warn", "output": singboxLogPath},
		"inbounds": inbounds, "outbounds": outbounds,
		"route": map[string]interface{}{"auto_detect_interface": true, "final": "selector"},
	}
}
func handlePing(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) { return }
	s := loadSettings()
	var path string
	if s.Engine == "sing-box" { path = singboxConfig } else { path = xrayConfigPath }
	configMutex.Lock()
	data, err := os.ReadFile(path)
	configMutex.Unlock()
	if err != nil { writeError(w, http.StatusInternalServerError, "Нет конфига"); return }
	var cfg map[string]interface{}
	json.Unmarshal(data, &cfg)
	outbounds, _ := cfg["outbounds"].([]interface{})
	
	results := make(map[string]interface{})
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, obRaw := range outbounds {
		ob, ok := obRaw.(map[string]interface{})
		if !ok { continue }
		tag, _ := ob["tag"].(string)
		server, _ := ob["server"].(string)
		portRaw, exists := ob["port"]
		if !exists { portRaw, exists = ob["server_port"] }
		if tag == "" || server == "" || !exists || tag == selectorTag || tag == "direct" || tag == "block" || tag == "selector" { continue }
		
		var port int
		if pFloat, ok := portRaw.(float64); ok { port = int(pFloat) } else if pInt, ok := portRaw.(int); ok { port = pInt }
		if port == 0 { continue }

		wg.Add(1)
		go func(t, s string, p int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", s, p)
			conn, err := net.DialTimeout("tcp", addr, pingTimeout)
			if err != nil {
				mu.Lock(); results[t] = "timeout"; mu.Unlock()
				return
			}
			conn.Close()
			mu.Lock(); results[t] = "OK"; mu.Unlock()
		}(tag, server, port)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "ping": results})
}

func readServerGroups() ([]ServerGroup, string, error) {
	s := loadSettings()
	path := xrayConfigPath
	if s.Engine == "sing-box" { path = singboxConfig }
	data, err := os.ReadFile(path)
	if err != nil { return nil, "", err }
	var cfg map[string]interface{}
	json.Unmarshal(data, &cfg)
	outboundsRaw, _ := cfg["outbounds"].([]interface{})
	
	var active string
	var allTags []string
	serversMap := make(map[string]ServerInfo)

	for _, obRaw := range outboundsRaw {
		ob, _ := obRaw.(map[string]interface{})
		tag, _ := ob["tag"].(string)
		if tag == selectorTag || tag == "selector" {
			var list interface{}
			if s.Engine == "sing-box" { list = ob["outbounds"] } else { list = ob["settings"].(map[string]interface{})["outbounds"] }
			if slice, ok := list.([]interface{}); ok && len(slice) > 0 {
				if str, ok := slice[0].(string); ok { active = str }
			}
			continue
		}
		server, _ := ob["server"].(string)
		portRaw, exists := ob["port"]
		if !exists { portRaw, _ = ob["server_port"] }
		var port int
		if pFloat, ok := portRaw.(float64); ok { port = int(pFloat) } else if pInt, ok := portRaw.(int); ok { port = pInt }
		if tag == "" || server == "" { continue }
		
		proto, _ := ob["protocol"].(string)
		if proto == "" { proto, _ = ob["type"].(string) }
		
		serversMap[tag] = ServerInfo{Tag: tag, Protocol: proto, Server: server, Port: port, Active: false}
		allTags = append(allTags, tag)
	}

	if active != "" {
		if srv, ok := serversMap[active]; ok { srv.Active = true; serversMap[active] = srv }
	}

	meta := loadGroupMeta()
	groupToServers := make(map[string][]ServerInfo)
	for _, tag := range allTags {
		info := serversMap[tag]
		gLabel := meta[tag]
		if gLabel == "" { gLabel = "Другие серверы" }
		groupToServers[gLabel] = append(groupToServers[gLabel], info)
	}

	var groups []ServerGroup
	links := loadSubLinks()
	for _, l := range links {
		if srvs, exists := groupToServers[l.Label]; exists {
			groups = append(groups, ServerGroup{Label: l.Label, Servers: srvs})
			delete(groupToServers, l.Label)
		}
	}
	for gLabel, srvs := range groupToServers {
		groups = append(groups, ServerGroup{Label: gLabel, Servers: srvs})
	}
	return groups, active, nil
}
func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) { return }
	if r.Method != http.MethodPost { writeError(w, http.StatusMethodNotAllowed, "Нужен POST"); return }
	var s AppSettings
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil { writeError(w, http.StatusBadRequest, "Кривые настройки"); return }
	saveSettings(s)
	_ = restartActiveEngine()
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func handleSelectServer(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) { return }
	if r.Method != http.MethodPost { writeError(w, http.StatusMethodNotAllowed, "Нужен POST"); return }
	var req selectServerRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	s := loadSettings()
	configMutex.Lock()
	defer configMutex.Unlock()

	path := xrayConfigPath
	if s.Engine == "sing-box" { path = singboxConfig }
	data, _ := os.ReadFile(path)
	var cfg map[string]interface{}
	json.Unmarshal(data, &cfg)
	outboundsRaw, _ := cfg["outbounds"].([]interface{})
	
	for _, obRaw := range outboundsRaw {
		ob, _ := obRaw.(map[string]interface{})
		tag, _ := ob["tag"].(string)
		if tag == selectorTag || tag == "selector" {
			var current []string
			if s.Engine == "sing-box" {
				tagsRaw, _ := ob["outbounds"].([]interface{})
				for _, t := range tagsRaw { if s, ok := t.(string); ok { current = append(current, s) } }
				reordered := moveTagFirst(current, req.Tag)
				newTags := make([]interface{}, len(reordered))
				for i, s := range reordered { newTags[i] = s }
				ob["outbounds"] = newTags
			} else {
				tagsRaw, _ := ob["settings"].(map[string]interface{})["outbounds"].([]interface{})
				for _, t := range tagsRaw { if s, ok := t.(string); ok { current = append(current, s) } }
				reordered := moveTagFirst(current, req.Tag)
				newTags := make([]interface{}, len(reordered))
				for i, s := range reordered { newTags[i] = s }
				ob["settings"].(map[string]interface{})["outbounds"] = newTags
			}
			break
		}
	}
	newData, _ := json.MarshalIndent(cfg, "", " ")
	_ = os.WriteFile(path, newData, 0644)
	_ = restartActiveEngine()
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "active_server": req.Tag})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) { return }
	s := loadSettings()
	path := xrayLogPath
	if s.Engine == "sing-box" { path = singboxLogPath }
	file, err := os.Open(path)
	if err != nil { writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "logs": []string{"Лог пуст."}}); return }
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() { lines = append(lines, scanner.Text()) }
	start := 0
	if len(lines) > 25 { start = len(lines) - 25 }
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "logs": lines[start:]})
}

func handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) { return }
	_ = exec.Command("killall", "-9", "xray", "sing-box").Run()
	_ = exec.Command("ndm", "-c", "no opkg proxy upstream vless").Run()
	_ = exec.Command("ndm", "-c", "system configuration save").Run()

	connMu.Lock()
	connectedAt = time.Time{}
	connMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) { return }
	_ = restartActiveEngine()
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func isActiveEngineRunning() bool {
	s := loadSettings()
	name := "xray"
	if s.Engine == "sing-box" { name = "sing-box" }
	out, err := exec.Command("pidof", name).Output()
	if err != nil { return false }
	return len(strings.TrimSpace(string(out))) > 0
}

func isProcessRunning(name string) bool {
	out, err := exec.Command("pidof", name).Output()
	if err != nil { return false }
	return len(strings.TrimSpace(string(out))) > 0
}

func readSelectorServers() ([]string, string, error) {
	s := loadSettings()
	path := xrayConfigPath
	if s.Engine == "sing-box" { path = singboxConfig }
	data, err := os.ReadFile(path)
	if err != nil { return nil, "", err }
	var cfg map[string]interface{}
	json.Unmarshal(data, &cfg)
	outboundsRaw, _ := cfg["outbounds"].([]interface{})
	for _, obRaw := range outboundsRaw {
		ob, _ := obRaw.(map[string]interface{})
		tag, _ := ob["tag"].(string)
		if tag == selectorTag || tag == "selector" {
			var tagsRaw []interface{}
			if s.Engine == "sing-box" { tagsRaw, _ = ob["outbounds"].([]interface{}) } else { tagsRaw, _ = ob["settings"].(map[string]interface{})["outbounds"].([]interface{}) }
			tags := make([]string, 0, len(tagsRaw))
			for _, t := range tagsRaw { if s, ok := t.(string); ok { tags = append(tags, s) } }
			active := ""
			if len(tags) > 0 { active = tags[0] }
			return tags, active, nil
		}
	}
	return nil, "", fmt.Errorf("err")
}

func moveTagFirst(tags []string, chosen string) []string {
	present := false
	for _, t := range tags { if t == chosen { present = true; break } }
	if !present { return tags }
	result := make([]string, 0, len(tags))
	result = append(result, chosen)
	for _, t := range tags { if t != chosen { result = append(result, t) } }
	return result
}

func uptimeSeconds() int64 {
	connMu.Lock()
	defer connMu.Unlock()
	if !isActiveEngineRunning() || connectedAt.IsZero() { return 0 }
	return int64(time.Since(connectedAt).Seconds())
}

func restartActiveEngine() error {
	_ = exec.Command("killall", "-9", "xray", "sing-box").Run()
	time.Sleep(200 * time.Millisecond)
	s := loadSettings()
	if s.Engine != "sing-box" {
		exec.Command("ndm", "-c", fmt.Sprintf("opkg proxy upstream vless socks 127.0.0.1:%d", s.SocksPort)).Run()
		exec.Command("ndm", "-c", "system configuration save").Run()
	} else {
		_ = exec.Command("ndm", "-c", "no opkg proxy upstream vless").Run()
		_ = exec.Command("ndm", "-c", "system configuration save").Run()
	}
	connMu.Lock()
	connectedAt = time.Now()
	connMu.Unlock()
	if s.Engine == "sing-box" { return exec.Command(singboxBinPath, "run", "-c", singboxConfig).Start() }
	return exec.Command(xrayBinPath, "run", "-c", xrayConfigPath).Start()
}
