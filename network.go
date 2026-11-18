package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Quién está conectado a la red. Fuente principal: el panel del router
// (instantáneo y exacto). Si no está configurado o falla, se recurre a un
// barrido de ping + tabla ARP desde este servidor.

const maxSweepHosts = 1024

var isWindows = runtime.GOOS == "windows"

type netInfo struct {
	Interface string
	IP        string
	MAC       string
	Prefix    netip.Prefix
	Gateway   string
}

func localIP() string {
	conn, err := net.Dial("udp4", "1.1.1.1:80") // UDP: no envía nada, solo elige la ruta
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

var (
	reGatewayLinux   = regexp.MustCompile(`default via (\d+\.\d+\.\d+\.\d+)`)
	reGatewayWindows = regexp.MustCompile(`(?m)^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)`)
	reArpWindows     = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})`)
	reOUI            = regexp.MustCompile(`^([0-9A-Fa-f]{6})\s+(?:\(base 16\)\s+)?(.+)$`)
)

func gateway() string {
	var out string
	re := reGatewayLinux
	if isWindows {
		out, _ = run(5*time.Second, "route", "print", "-4", "0.0.0.0")
		re = reGatewayWindows
	} else {
		out, _ = run(5*time.Second, "ip", "-4", "route", "show", "default")
	}
	if match := re.FindStringSubmatch(out); match != nil {
		return match[1]
	}
	return ""
}

func detectNetwork() (*netInfo, error) {
	local := localIP()
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		if cfg.Network.Interface != "" && iface.Name != cfg.Network.Interface {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			if cfg.Network.Interface == "" && ipnet.IP.String() != local {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			prefix := netip.PrefixFrom(netip.MustParseAddr(ipnet.IP.To4().String()), ones)
			if cfg.Network.Subnet != "" {
				if prefix, err = netip.ParsePrefix(cfg.Network.Subnet); err != nil {
					return nil, fmt.Errorf("subred inválida: %s", cfg.Network.Subnet)
				}
			}
			if prefix.Bits() < 22 { // demasiado grande para barrer: limitar a /24
				prefix = netip.PrefixFrom(prefix.Addr(), 24)
			}
			return &netInfo{
				Interface: iface.Name, IP: ipnet.IP.String(),
				MAC: iface.HardwareAddr.String(), Prefix: prefix.Masked(), Gateway: gateway(),
			}, nil
		}
	}
	return nil, errors.New("No se pudo detectar la red local")
}

// ---------- barrido de respaldo ----------

func ping(ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	args := []string{"-c", "1", "-W", "1", ip}
	if isWindows {
		args = []string{"-n", "1", "-w", "800", ip}
	}
	return exec.CommandContext(ctx, "ping", args...).Run() == nil
}

func sweep(prefix netip.Prefix) map[string]bool {
	alive := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	limit := make(chan struct{}, 64)
	count := 0
	for addr := prefix.Addr().Next(); prefix.Contains(addr) && count < maxSweepHosts; addr = addr.Next() {
		count++
		wg.Add(1)
		limit <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			if ping(ip) {
				mu.Lock()
				alive[ip] = true
				mu.Unlock()
			}
			<-limit
		}(addr.String())
	}
	wg.Wait()
	return alive
}

func isUnicast(mac string) bool {
	first, err := strconv.ParseUint(mac[:2], 16, 8)
	return err == nil && mac != "00:00:00:00:00:00" && first&1 == 0
}

// neighbors devuelve ip -> mac de los equipos presentes ahora mismo.
func neighbors(info *netInfo, alive map[string]bool) map[string]string {
	found := map[string]string{}
	inSubnet := func(ip string) bool {
		addr, err := netip.ParseAddr(ip)
		return err == nil && info.Prefix.Contains(addr)
	}
	if isWindows {
		out, _ := run(5*time.Second, "arp", "-a")
		for _, match := range reArpWindows.FindAllStringSubmatch(out, -1) {
			mac := normalizeMAC(match[2])
			if mac != "" && inSubnet(match[1]) && isUnicast(mac) {
				found[match[1]] = mac
			}
		}
		return found
	}
	out, _ := run(5*time.Second, "ip", "-4", "neigh", "show", "dev", info.Interface)
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		mac := ""
		for i, part := range parts[:len(parts)-1] {
			if part == "lladdr" {
				mac = normalizeMAC(parts[i+1])
			}
		}
		state := parts[len(parts)-1]
		fresh := state == "REACHABLE" || state == "DELAY" || state == "PERMANENT" || alive[parts[0]]
		if mac != "" && fresh && inSubnet(parts[0]) && isUnicast(mac) {
			found[parts[0]] = mac
		}
	}
	return found
}

// ---------- nombres y fabricantes ----------

var (
	ouiOnce  sync.Once
	ouiTable map[string]string
	ouiFiles = []string{
		"data/oui.txt", // relativo al config
		"/usr/share/nmap/nmap-mac-prefixes",
		"/usr/share/arp-scan/ieee-oui.txt",
		"/usr/share/hwdata/oui.txt",
		"/usr/share/ieee-data/oui.txt",
		"/var/lib/ieee-data/oui.txt",
	}
)

func vendorFor(mac string) string {
	if first, err := strconv.ParseUint(mac[:2], 16, 8); err == nil && first&2 != 0 {
		return "MAC privada (aleatoria)"
	}
	ouiOnce.Do(func() {
		ouiTable = map[string]string{}
		for _, path := range ouiFiles {
			file, err := os.Open(resolvePath(path))
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				if match := reOUI.FindStringSubmatch(strings.TrimSpace(scanner.Text())); match != nil {
					ouiTable[strings.ToUpper(match[1])] = strings.TrimSpace(match[2])
				}
			}
			file.Close()
			if len(ouiTable) > 0 {
				log.Printf("Fabricantes cargados desde %s (%d)", path, len(ouiTable))
				return
			}
		}
	})
	return ouiTable[strings.ToUpper(strings.ReplaceAll(mac, ":", "")[:6])]
}

func leaseNames() map[string]string {
	names := map[string]string{}
	for _, path := range []string{"/var/lib/misc/dnsmasq.leases", "/var/lib/dnsmasq/dnsmasq.leases"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if parts := strings.Fields(line); len(parts) >= 4 && parts[3] != "*" {
				names[strings.ToLower(parts[1])] = parts[3]
			}
		}
	}
	return names
}

// fillHostnames completa los nombres que falten por DHCP local o DNS inverso.
func fillHostnames(found []seenDevice) {
	leases := leaseNames()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := range found {
		if found[i].Hostname != "" || found[i].IP == "" {
			continue
		}
		if name, ok := leases[found[i].MAC]; ok {
			found[i].Hostname = name
			continue
		}
		wg.Add(1)
		go func(d *seenDevice) {
			defer wg.Done()
			names, err := net.DefaultResolver.LookupAddr(ctx, d.IP)
			if err == nil && len(names) > 0 {
				d.Hostname, _, _ = strings.Cut(strings.TrimSuffix(names[0], "."), ".")
			}
		}(&found[i])
	}
	wg.Wait()
}

// ---------- escáner ----------

type NetworkScanner struct {
	store  *Store
	notify func(typ, message, mac string, push bool)

	scanMu sync.Mutex // un escaneo a la vez

	mu          sync.Mutex
	info        *netInfo
	lastScan    float64
	lastError   string
	source      string
	scanning    bool
	routerPause time.Time // no reintentar el login del router antes de esto
	routerInfo  *routerStatus
}

func (n *NetworkScanner) routerEnabled() bool {
	return cfg.Router.Type == "zte" && secrets.RouterPassword != ""
}

func routerURL(info *netInfo) string {
	if cfg.Router.URL != "" {
		return cfg.Router.URL
	}
	return "http://" + info.Gateway
}

func (n *NetworkScanner) fromRouter(info *netInfo) ([]seenDevice, error) {
	n.mu.Lock()
	paused := time.Until(n.routerPause)
	n.mu.Unlock()
	if paused > 0 {
		return nil, fmt.Errorf("login del router en pausa %d min tras un rechazo", int(paused.Minutes())+1)
	}
	client := newZTEClient(routerURL(info), cfg.Router.Username, secrets.RouterPassword)
	devices, err := client.devices()
	if isSessionError(err) {
		// Sesión cortada a mitad (otro login): reconectar una vez
		client = newZTEClient(routerURL(info), cfg.Router.Username, secrets.RouterPassword)
		devices, err = client.devices()
	}
	if err != nil {
		if errors.Is(err, errRouterAuth) {
			// Insistir con una contraseña mala bloquea el panel del router.
			n.mu.Lock()
			n.routerPause = time.Now().Add(15 * time.Minute)
			n.mu.Unlock()
		}
		return nil, err
	}
	n.mu.Lock()
	n.routerInfo = client.info
	n.mu.Unlock()
	if client.blocked != nil {
		n.store.syncBlocked(client.blocked)
	}
	for _, mac := range client.moved {
		n.notify("block", "Equipo bloqueado intentó entrar por otra banda: "+mac+" (bloqueo movido)", mac, true)
	}
	found := make([]seenDevice, 0, len(devices))
	seen := map[string]bool{}
	for _, d := range devices {
		if seen[d.MAC] {
			continue
		}
		seen[d.MAC] = true
		found = append(found, seenDevice{MAC: d.MAC, IP: d.IP, Hostname: d.Hostname, Conn: d.Conn,
			SSID: d.SSID, Port: d.Port, Signal: d.Signal})
	}
	return found, nil
}

// setBlocked bloquea o desbloquea un dispositivo en el filtro MAC del router.
// Es una orden del usuario: si otra persona tiene el panel abierto, se la expulsa.
func (n *NetworkScanner) setBlocked(mac string, block bool) error {
	if !n.routerEnabled() {
		return errors.New("Bloquear requiere tener el router configurado")
	}
	n.scanMu.Lock() // el router solo admite una sesión: no coincidir con un escaneo
	defer n.scanMu.Unlock()
	info, err := detectNetwork()
	if err != nil {
		return err
	}
	ssid := ""
	if device, ok := n.store.device(mac); ok {
		ssid = device.SSID
	}
	client := newZTEClient(routerURL(info), cfg.Router.Username, secrets.RouterPassword)
	client.force = true
	if err := client.setBlocked(mac, block, ssid); err != nil {
		log.Printf("Router: fallo al %s %s: %v", map[bool]string{true: "bloquear", false: "desbloquear"}[block], mac, err)
		return err
	}
	n.store.setBlocked(mac, block)
	return nil
}

func fromSweep(info *netInfo) []seenDevice {
	alive := sweep(info.Prefix)
	time.Sleep(1500 * time.Millisecond) // deja que el kernel termine de resolver ARP
	var found []seenDevice
	for ip, mac := range neighbors(info, alive) {
		found = append(found, seenDevice{MAC: mac, IP: ip})
	}
	return found
}

func (n *NetworkScanner) scan() {
	n.scanMu.Lock()
	defer n.scanMu.Unlock()
	n.setScanning(true)
	defer n.setScanning(false)

	info, err := detectNetwork()
	if err != nil {
		n.fail(err.Error())
		return
	}
	firstRun := n.store.deviceCount() == 0

	var found []seenDevice
	source, warning := "scan", ""
	if n.routerEnabled() {
		if found, err = n.fromRouter(info); err == nil {
			source = "router"
		} else {
			warning = "Router: " + err.Error() + " (usando escaneo ARP)"
			log.Print(warning)
		}
	}
	if source == "scan" {
		found = fromSweep(info)
	}

	// Este servidor siempre está presente
	self := normalizeMAC(info.MAC)
	hostname, _ := os.Hostname()
	hasSelf := false
	for i := range found {
		if found[i].MAC == self {
			hasSelf = true
			found[i].Hostname = hostname
		}
	}
	if !hasSelf && self != "" {
		found = append(found, seenDevice{MAC: self, IP: info.IP, Hostname: hostname})
	}
	fillHostnames(found)
	for i := range found {
		found[i].Vendor = vendorFor(found[i].MAC)
	}

	fresh := n.store.markSeen(found)
	n.mu.Lock()
	n.info, n.lastScan, n.lastError, n.source = info, nowTS(), warning, source
	n.mu.Unlock()
	log.Printf("Red (%s): %d dispositivos, %d nuevos", source, len(found), len(fresh))

	if firstRun {
		known := true
		n.store.updateDevice(self, nil, nil, &known)
		n.notify("scan", fmt.Sprintf("Primer escaneo: %d dispositivos en %s", len(found), info.Prefix), "", false)
		return
	}
	for _, d := range fresh {
		label := d.Hostname
		if label == "" {
			label = d.Vendor
		}
		if label == "" {
			label = "desconocido"
		}
		n.notify("new_device", fmt.Sprintf("Nuevo dispositivo en la red: %s (%s, %s)", label, d.IP, d.MAC), d.MAC, true)
	}
}

func (n *NetworkScanner) setScanning(on bool) {
	n.mu.Lock()
	n.scanning = on
	n.mu.Unlock()
}

func (n *NetworkScanner) fail(message string) {
	log.Print(message)
	n.mu.Lock()
	n.lastError = message
	n.mu.Unlock()
}

type deviceView struct {
	Device
	Online    bool `json:"online"`
	IsSelf    bool `json:"is_self"`
	IsGateway bool `json:"is_gateway"`
}

func (n *NetworkScanner) snapshot() M {
	n.mu.Lock()
	info, lastScan, lastError, source, scanning := n.info, n.lastScan, n.lastError, n.source, n.scanning
	routerInfo := n.routerInfo
	n.mu.Unlock()

	now := nowTS()
	selfMAC, gatewayIP := "", ""
	result := M{"subnet": nil, "interface": nil, "gateway": nil, "server_ip": nil}
	if info != nil {
		selfMAC, gatewayIP = normalizeMAC(info.MAC), info.Gateway
		result = M{"subnet": info.Prefix.String(), "interface": info.Interface,
			"gateway": info.Gateway, "server_ip": info.IP}
	}

	devices := []deviceView{}
	online, unknown := 0, 0
	for _, d := range n.store.devices() {
		view := deviceView{
			Device:    d,
			Online:    now-d.LastSeen < float64(cfg.Network.OfflineAfterSeconds),
			IsSelf:    d.MAC == selfMAC,
			IsGateway: gatewayIP != "" && d.IP == gatewayIP,
		}
		if view.Online {
			online++
		}
		if !d.Known {
			unknown++
		}
		devices = append(devices, view)
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Online != devices[j].Online {
			return devices[i].Online
		}
		a, _ := netip.ParseAddr(devices[i].IP)
		b, _ := netip.ParseAddr(devices[j].IP)
		return a.Less(b)
	})

	result["source"] = source
	result["can_block"] = n.routerEnabled()
	result["router"] = nil
	if routerInfo != nil && source == "router" {
		result["router"] = routerInfo
	}
	result["last_scan"] = nil
	if lastScan > 0 {
		result["last_scan"] = lastScan
	}
	result["error"] = nil
	if lastError != "" {
		result["error"] = lastError
	}
	result["scanning"] = scanning
	result["online"] = online
	result["unknown"] = unknown
	result["devices"] = devices
	return result
}
