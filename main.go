package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	appDir       = "/opt/etc/happ-keenetic"
	stateFile    = "state.json"
	settingsFile = "settings.json"
	subMetaFile  = "sub_meta.json"
	staticFile   = "static.html"
	xrayBin      = "/opt/sbin/xray"
	singBoxBin   = "/opt/sbin/sing-box"
	xrayConfig   = "/opt/etc/xray/config.json"
	singConfig   = "/opt/etc/sing-box/config.json"
	cronFile     = "/opt/etc/crontab"
)

type AppSettings struct {
	ListenAddr  string `json:"listen_addr"`
	SocksPort   int    `json:"socks_port"`
	HttpPort    int    `json:"http_port"`
	RedirPort   int    `json:"redir_port"`
	CronCheck   bool   `json:"cron_check"`
	Engine      string `json:"engine"`       // "xray" | "sing-box"
	RoutingMode string `json:"routing_mode"` // "none" | "redirect"
}

type AppState struct {
	Subscriptions []SubEntry `json:"subscriptions"`
	ActiveSubID   string     `json:"active_sub_id"`
	ActiveTag     string     `json:"active_tag"`
	Connected     bool       `json:"connected"`
}

type SubEntry struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Fallback string `json:"fallback"`
	Title    string `json:"title"`
}

var (
	mu       sync.RWMutex
	settings AppSettings
	state    AppState
	subMeta  SubMeta
)

func main() {
	os.MkdirAll(appDir, 0755)
	os.MkdirAll("/opt/etc/xray", 0755)
	os.MkdirAll("/opt/etc/sing-box", 0755)
	os.MkdirAll("/opt/var/log/xray", 0755)

	loadSettings()
	loadState()
	loadSubMeta()

	if settings.ListenAddr == "" {
		settings.ListenAddr = ":3333"
	}
	if settings.SocksPort == 0 {
		settings.SocksPort = 10808
	}
	if settings.HttpPort == 0 {
		settings.HttpPort = 10809
	}
	if settings.RedirPort == 0 {
		settings.RedirPort = 12345
	}
	if settings.Engine == "" {
		settings.Engine = "xray"
	}
	if settings.RoutingMode == "" {
		settings.RoutingMode = "none"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/settings", handleSettings)
	mux.HandleFunc("/api/subscriptions", handleSubscriptions)
	mux.HandleFunc("/api/sync", handleSync)
	mux.HandleFunc("/api/connect", handleConnect)
	mux.HandleFunc("/api/disconnect", handleDisconnect)
	mux.HandleFunc("/api/ping", handlePing)

	// v2.3: awg-manager compatible endpoints
	mux.HandleFunc("/api/awg-sub/", handleAWGSub)
	mux.HandleFunc("/api/share-links/", handleShareLinks)
	mux.HandleFunc("/api/singbox-config/", handleSingboxConfig)

	mux.HandleFunc("/", handleStatic)

	log.Printf("happ-keenetic v2.3 starting on %s", settings.ListenAddr)
	log.Fatal(http.ListenAndServe(settings.ListenAddr, mux))
}

// ---------- Storage ----------

func loadSettings() {
	p := filepath.Join(appDir, settingsFile)
	b, _ := os.ReadFile(p)
	json.Unmarshal(b, &settings)
}

func saveSettings() {
	b, _ := json.MarshalIndent(settings, "", "  ")
	os.WriteFile(filepath.Join(appDir, settingsFile), b, 0644)
}

func loadState() {
	p := filepath.Join(appDir, stateFile)
	b, _ := os.ReadFile(p)
	json.Unmarshal(b, &state)
}

func saveState() {
	b, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile(filepath.Join(appDir, stateFile), b, 0644)
}

func loadSubMeta() {
	p := filepath.Join(appDir, subMetaFile)
	b, _ := os.ReadFile(p)
	json.Unmarshal(b, &subMeta)
}

func saveSubMeta() {
	b, _ := json.MarshalIndent(subMeta, "", "  ")
	os.WriteFile(filepath.Join(appDir, subMetaFile), b, 0644)
}

// ---------- Handlers ----------

func handleStatus(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()

	resp := map[string]interface{}{
		"settings":      settings,
		"state":         state,
		"sub_meta":      subMeta,
		"engines":       []string{"xray", "sing-box"},
		"routing_modes": []string{"none", "redirect"},
	}
	json.NewEncoder(w).Encode(resp)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var s AppSettings
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mu.Lock()
		if s.ListenAddr != "" {
			settings.ListenAddr = s.ListenAddr
		}
		if s.Engine != "" {
			settings.Engine = s.Engine
		}
		if s.RoutingMode != "" {
			settings.RoutingMode = s.RoutingMode
		}
		if s.SocksPort != 0 {
			settings.SocksPort = s.SocksPort
		}
		if s.HttpPort != 0 {
			settings.HttpPort = s.HttpPort
		}
		if s.RedirPort != 0 {
			settings.RedirPort = s.RedirPort
		}
		settings.CronCheck = s.CronCheck
		mu.Unlock()
		saveSettings()
		updateCron()
	}
	handleStatus(w, r)
}

func handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(state.Subscriptions)

	case http.MethodPost:
		var sub SubEntry
		if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if sub.ID == "" {
			sub.ID = hashURL(sub.URL)
		}
		state.Subscriptions = append(state.Subscriptions, sub)
		saveState()
		json.NewEncoder(w).Encode(sub)

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		filtered := make([]SubEntry, 0, len(state.Subscriptions))
		for _, s := range state.Subscriptions {
			if s.ID != id {
				filtered = append(filtered, s)
			}
		}
		state.Subscriptions = filtered
		if state.ActiveSubID == id {
			state.ActiveSubID = ""
			state.ActiveTag = ""
			state.Connected = false
			stopEngine()
		}
		saveState()
		w.WriteHeader(204)
	}
}

func handleSync(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	var allServers []ServerConfig
	newMeta := SubMeta{Servers: map[string][]ServerConfig{}}

	for _, sub := range state.Subscriptions {
		if sub.URL == "" {
			continue
		}
		result, err := fetchSubscription(sub.URL, sub.Fallback)
		if err != nil {
			log.Printf("sync error for %s: %v", sub.URL, err)
			continue
		}
		newMeta.ProfileTitle = result.ProfileTitle
		newMeta.ProfileUpdateInterval = result.ProfileUpdateInterval
		newMeta.SubscriptionUserinfo = result.SubscriptionUserinfo
		newMeta.SupportURL = result.SupportURL
		newMeta.FallbackURL = result.FallbackURL
		newMeta.Announce = result.Announce

		activeFound := false
		for i := range result.Servers {
			result.Servers[i].SubID = sub.ID
			if result.Servers[i].Tag == state.ActiveTag {
				activeFound = true
			}
		}
		if !activeFound && state.ActiveSubID == sub.ID && len(result.Servers) > 0 {
			state.ActiveTag = result.Servers[0].Tag
		}

		newMeta.Servers[sub.ID] = result.Servers
		allServers = append(allServers, result.Servers...)
	}

	subMeta = newMeta
	saveSubMeta()
	saveState()

	updateCron()

	resp := map[string]interface{}{
		"ok":      true,
		"servers": allServers,
		"meta":    subMeta,
	}
	json.NewEncoder(w).Encode(resp)
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		SubID string `json:"sub_id"`
		Tag   string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	servers, ok := subMeta.Servers[req.SubID]
	if !ok {
		http.Error(w, "subscription not found", 404)
		return
	}

	var selected *ServerConfig
	for i := range servers {
		if servers[i].Tag == req.Tag {
			selected = &servers[i]
			break
		}
	}
	if selected == nil {
		http.Error(w, "server not found", 404)
		return
	}

	state.ActiveSubID = req.SubID
	state.ActiveTag = req.Tag
	state.Connected = true
	saveState()

	if err := restartEngine(selected); err != nil {
		state.Connected = false
		saveState()
		http.Error(w, err.Error(), 500)
		return
	}

	w.WriteHeader(204)
}

func handleDisconnect(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	state.Connected = false
	state.ActiveTag = ""
	saveState()
	stopEngine()
	w.WriteHeader(204)
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	subID := r.URL.Query().Get("sub_id")

	mu.RLock()
	servers, ok := subMeta.Servers[subID]
	mu.RUnlock()
	if !ok {
		http.Error(w, "not found", 404)
		return
	}

	var srv *ServerConfig
	for i := range servers {
		if servers[i].Tag == tag {
			srv = &servers[i]
			break
		}
	}
	if srv == nil {
		http.Error(w, "server not found", 404)
		return
	}

	timeout := 3 * time.Second
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(srv.Address, strconv.Itoa(srv.Port)), timeout)
	duration := time.Since(start)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error(), "ms": int(duration.Milliseconds())})
		return
	}
	conn.Close()
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "ms": int(duration.Milliseconds())})
}

// ---------- AWG-Manager bridge (v2.3) ----------

func handleAWGSub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", 405)
		return
	}
	subID := strings.TrimPrefix(r.URL.Path, "/api/awg-sub/")
	if subID == "" {
		http.Error(w, "missing sub_id", 400)
		return
	}

	mu.RLock()
	servers, ok := subMeta.Servers[subID]
	mu.RUnlock()
	if !ok {
		http.Error(w, "subscription not found", 404)
		return
	}

	outbounds := make([]map[string]interface{}, 0, len(servers))
	for _, srv := range servers {
		sb := ToSingboxOutbound(srv.Outbound, srv.Name)
		if sb != nil {
			outbounds = append(outbounds, sb)
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Subscription-Userinfo", subMeta.SubscriptionUserinfo)
	w.Header().Set("Profile-Title", subMeta.ProfileTitle)
	w.Header().Set("Profile-Update-Interval", subMeta.ProfileUpdateInterval)
	json.NewEncoder(w).Encode(outbounds)
}

func handleShareLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", 405)
		return
	}
	subID := strings.TrimPrefix(r.URL.Path, "/api/share-links/")
	if subID == "" {
		http.Error(w, "missing sub_id", 400)
		return
	}

	mu.RLock()
	servers, ok := subMeta.Servers[subID]
	mu.RUnlock()
	if !ok {
		http.Error(w, "subscription not found", 404)
		return
	}

	var lines []string
	for _, srv := range servers {
		sb := ToSingboxOutbound(srv.Outbound, srv.Name)
		if sb != nil {
			if link := ToShareLink(sb); link != "" {
				lines = append(lines, link)
			}
		}
	}

	body := strings.Join(lines, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(body))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Subscription-Userinfo", subMeta.SubscriptionUserinfo)
	w.Header().Set("Profile-Title", subMeta.ProfileTitle)
	w.Write([]byte(encoded))
}

func handleSingboxConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", 405)
		return
	}
	subID := strings.TrimPrefix(r.URL.Path, "/api/singbox-config/")
	if subID == "" {
		http.Error(w, "missing sub_id", 400)
		return
	}

	mu.RLock()
	servers, ok := subMeta.Servers[subID]
	mu.RUnlock()
	if !ok {
		http.Error(w, "subscription not found", 404)
		return
	}

	tag := r.URL.Query().Get("tag")
	var selected *ServerConfig
	for i := range servers {
		if tag == "" || servers[i].Tag == tag {
			selected = &servers[i]
			break
		}
	}
	if selected == nil {
		http.Error(w, "server not found", 404)
		return
	}

	sb := ToSingboxOutbound(selected.Outbound, selected.Name)
	if sb == nil {
		http.Error(w, "unsupported protocol", 500)
		return
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"level":  "warn",
			"output": "/opt/var/log/xray/error.log",
		},
		"inbounds": []map[string]interface{}{
			{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": settings.SocksPort},
			{"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": settings.HttpPort},
		},
		"outbounds": []map[string]interface{}{
			sb,
			{"type": "direct", "tag": "direct"},
			{"type": "block", "tag": "block"},
		},
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.MarshalIndent(cfg, "", "  ")
	w.Write(b)
}

// ---------- Static UI (reads from disk) ----------

func handleStatic(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(filepath.Join(appDir, staticFile))
	if err != nil {
		http.Error(w, "UI not found", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// ---------- Engine management ----------

func restartEngine(srv *ServerConfig) error {
	stopEngine()

	var cfg map[string]interface{}
	if settings.Engine == "xray" {
		cfg = buildXrayConfig(srv)
	} else {
		cfg = buildSingboxConfig(srv)
	}

	b, _ := json.MarshalIndent(cfg, "", "  ")
	configPath := xrayConfig
	if settings.Engine == "sing-box" {
		configPath = singConfig
	}
	if err := os.WriteFile(configPath, b, 0644); err != nil {
		return err
	}

	bin := xrayBin
	if settings.Engine == "sing-box" {
		bin = singBoxBin
	}
	cmd := exec.Command(bin, "-c", configPath)
	if err := cmd.Start(); err != nil {
		return err
	}

	time.Sleep(500 * time.Millisecond)

	if settings.RoutingMode == "redirect" {
		applyRedirectRules(true)
	}

	return nil
}

func stopEngine() {
	applyRedirectRules(false)
	exec.Command("killall", "-9", "xray").Run()
	exec.Command("killall", "-9", "sing-box").Run()
	time.Sleep(200 * time.Millisecond)
}

func applyRedirectRules(enable bool) {
	if enable {
		exec.Command("sh", "-c", fmt.Sprintf(`iptables -t nat -N HAPP_REDIR 2>/dev/null
iptables -t nat -F HAPP_REDIR
iptables -t nat -A HAPP_REDIR -d 127.0.0.0/8 -j RETURN
iptables -t nat -A HAPP_REDIR -d 192.168.0.0/16 -j RETURN
iptables -t nat -A HAPP_REDIR -d 10.0.0.0/8 -j RETURN
iptables -t nat -A HAPP_REDIR -p tcp --dport 80 -j REDIRECT --to-ports %d
iptables -t nat -A HAPP_REDIR -p tcp --dport 443 -j REDIRECT --to-ports %d
iptables -t nat -C PREROUTING -j HAPP_REDIR 2>/dev/null || iptables -t nat -A PREROUTING -j HAPP_REDIR`, settings.RedirPort, settings.RedirPort)).Run()
	} else {
		exec.Command("sh", "-c", `iptables -t nat -D PREROUTING -j HAPP_REDIR 2>/dev/null
iptables -t nat -F HAPP_REDIR 2>/dev/null
iptables -t nat -X HAPP_REDIR 2>/dev/null`).Run()
	}
}

// ---------- Config builders ----------

func buildXrayConfig(srv *ServerConfig) map[string]interface{} {
	inbounds := []map[string]interface{}{
		{
			"tag":      "socks-in",
			"listen":   "127.0.0.1",
			"port":     settings.SocksPort,
			"protocol": "socks",
			"settings": map[string]interface{}{"auth": "noauth", "udp": true},
		},
		{
			"tag":      "http-in",
			"listen":   "127.0.0.1",
			"port":     settings.HttpPort,
			"protocol": "http",
			"settings": map[string]interface{}{},
		},
	}

	if settings.RoutingMode == "redirect" {
		inbounds = append(inbounds, map[string]interface{}{
			"tag":      "redir-in",
			"protocol": "dokodemo-door",
			"listen":   "0.0.0.0",
			"port":     settings.RedirPort,
			"settings": map[string]interface{}{"network": "tcp,udp", "followRedirect": true},
		})
	}

	outbounds := []map[string]interface{}{
		srv.Outbound,
		{"protocol": "freedom", "tag": "direct"},
		{"protocol": "blackhole", "tag": "block"},
	}

	return map[string]interface{}{
		"log": map[string]interface{}{
			"access":   "",
			"error":    "/opt/var/log/xray/error.log",
			"loglevel": "warning",
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
	}
}

func buildSingboxConfig(srv *ServerConfig) map[string]interface{} {
	inbounds := []map[string]interface{}{
		{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": settings.SocksPort},
		{"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": settings.HttpPort},
	}

	if settings.RoutingMode == "redirect" {
		inbounds = append(inbounds, map[string]interface{}{
			"type":                       "redirect",
			"tag":                        "redir-in",
			"listen":                     "0.0.0.0",
			"listen_port":                settings.RedirPort,
			"sniff":                      true,
			"sniff_override_destination": false,
		})
	}

	outbounds := []map[string]interface{}{
		srv.Outbound,
		{"type": "direct", "tag": "direct"},
		{"type": "block", "tag": "block"},
	}

	return map[string]interface{}{
		"log": map[string]interface{}{
			"level":  "warn",
			"output": "/opt/var/log/xray/error.log",
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
	}
}

// ---------- Subscription fetch ----------

func fetchSubscription(urlStr, fallback string) (*SubscriptionResult, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		if fallback != "" {
			return fetchSubscription(fallback, "")
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode <= 599 && fallback != "" {
		return fetchSubscription(fallback, "")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	result := &SubscriptionResult{}
	if v := resp.Header.Get("Subscription-Userinfo"); v != "" {
		result.SubscriptionUserinfo = v
	}
	if v := resp.Header.Get("Profile-Title"); v != "" {
		result.ProfileTitle = v
	}
	if v := resp.Header.Get("Profile-Update-Interval"); v != "" {
		result.ProfileUpdateInterval = v
	}
	if v := resp.Header.Get("Support-Url"); v != "" {
		result.SupportURL = v
	}
	if v := resp.Header.Get("Fallback-Url"); v != "" {
		result.FallbackURL = v
	}
	if v := resp.Header.Get("Announce"); v != "" {
		result.Announce = v
	}

	servers, err := ParseSubscription(body)
	if err != nil {
		return nil, err
	}
	result.Servers = servers
	return result, nil
}

func updateCron() {
	if !settings.CronCheck {
		exec.Command("sh", "-c", fmt.Sprintf("sed -i '/happ-keenetic.*api\\\\/sync/d' %s", cronFile)).Run()
		return
	}

	interval := 24
	if subMeta.ProfileUpdateInterval != "" {
		if v, err := strconv.Atoi(subMeta.ProfileUpdateInterval); err == nil && v > 0 {
			interval = v
		}
	}

	line := fmt.Sprintf("0 */%d * * * root curl -s -X POST http://127.0.0.1%s/api/sync >/dev/null 2>&1 # happ-keenetic auto-sync\n", interval, settings.ListenAddr)

	exec.Command("sh", "-c", fmt.Sprintf("sed -i '/happ-keenetic.*api\\\\/sync/d' %s", cronFile)).Run()
	f, _ := os.OpenFile(cronFile, os.O_APPEND|os.O_WRONLY, 0644)
	if f != nil {
		f.WriteString(line)
		f.Close()
	}
	exec.Command("/opt/etc/init.d/S10cron", "restart").Run()
}

func hashURL(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))[:8]
}
