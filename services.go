package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	psnet "github.com/shirou/gopsutil/v4/net"
)

// Servicios del servidor: unidades systemd y contenedores Docker.
// Los IDs tienen el formato "systemd:<unit>" o "docker:<nombre>".

type Service struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	Unit        string   `json:"unit"`
	Description string   `json:"description"`
	Watched     bool     `json:"watched"`
	State       string   `json:"state"`
	SubState    string   `json:"sub_state"`
	Running     bool     `json:"running"`
	Enabled     bool     `json:"enabled"`
	PID         *int     `json:"pid"`
	MemoryBytes *int64   `json:"memory_bytes"`
	CPUPercent  *float64 `json:"cpu_percent"`
	Ports       []int    `json:"ports"`
	Uptime      *int64   `json:"uptime_seconds"`
	Restarts    int      `json:"restarts"`
}

var showProps = "Id,Description,ActiveState,SubState,MainPID,ControlGroup,MemoryCurrent," +
	"CPUUsageNSec,ActiveEnterTimestampMonotonic,NRestarts,UnitFileState"

type cpuSample struct {
	at time.Time
	ns int64
}

type ServiceManager struct {
	mu          sync.Mutex
	store       *Store
	seen        map[string]bool
	cpuSamples  map[string]cpuSample
	dockerCache []Service
	dockerAt    time.Time
}

func newServiceManager(store *Store) *ServiceManager {
	return &ServiceManager{store: store, seen: map[string]bool{}, cpuSamples: map[string]cpuSample{}}
}

// run ejecuta un comando y devuelve stdout+stderr.
var run = func(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() != nil {
		return string(out), errors.New("el comando tardó demasiado")
	}
	return string(out), err
}

var hasCommand = func(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// watchedUnits devuelve unit -> nombre visible (config + fijados desde la app).
func (m *ServiceManager) watchedUnits() map[string]string {
	result := map[string]string{}
	for _, item := range cfg.Services.Watch {
		unit := item.Unit
		if unit == "" {
			continue
		}
		if !strings.Contains(unit, ".") {
			unit += ".service"
		}
		name := item.Name
		if name == "" {
			name = strings.TrimSuffix(unit, ".service")
		}
		result[unit] = name
	}
	for _, unit := range m.store.watched() {
		if _, ok := result[unit]; !ok {
			result[unit] = strings.TrimSuffix(unit, ".service")
		}
	}
	return result
}

func runningUnits() []string {
	out, _ := run(10*time.Second, "systemctl", "list-units", "--type=service", "--state=running",
		"--no-legend", "--plain", "--no-pager")
	var units []string
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			units = append(units, fields[0])
		}
	}
	return units
}

// parseInt devuelve nil para valores vacíos o "[not set]" (systemd usa 2^64-1).
func parseInt(value string) *int64 {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func cgroupPids(cgroup string) []int {
	if cgroup == "" {
		return nil
	}
	var pids []int
	root := filepath.Join("/sys/fs/cgroup", cgroup)
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "cgroup.procs" {
			return nil
		}
		raw, _ := os.ReadFile(path)
		for _, field := range strings.Fields(string(raw)) {
			if pid, err := strconv.Atoi(field); err == nil {
				pids = append(pids, pid)
			}
		}
		return nil
	})
	return pids
}

func listeningPorts() map[int][]int {
	ports := map[int][]int{}
	conns, err := psnet.Connections("inet")
	if err != nil {
		return ports
	}
	for _, c := range conns {
		if c.Status == "LISTEN" && c.Pid > 0 {
			ports[int(c.Pid)] = append(ports[int(c.Pid)], int(c.Laddr.Port))
		}
	}
	return ports
}

func systemUptime() float64 {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	up, _ := strconv.ParseFloat(fields[0], 64)
	return up
}

func (m *ServiceManager) systemdServices(listen map[int][]int) []Service {
	watched := m.watchedUnits()
	inList := map[string]bool{}
	var units []string
	add := func(unit string) {
		if !inList[unit] {
			inList[unit] = true
			units = append(units, unit)
		}
	}
	for unit := range watched {
		add(unit)
	}
	if cfg.Services.ShowAllRunning {
		for _, unit := range runningUnits() {
			add(unit)
		}
	}
	// Los servicios ya vistos siguen listados aunque se detengan
	for unit := range m.seen {
		add(unit)
	}
	if len(units) == 0 {
		return nil
	}

	args := append([]string{"show", "--no-pager", "--property=" + showProps}, units...)
	out, _ := run(10*time.Second, "systemctl", args...)
	now := time.Now()
	uptime := systemUptime()
	var services []Service
	for _, block := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n\n") {
		props := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if key, value, ok := strings.Cut(line, "="); ok {
				props[key] = value
			}
		}
		unit := props["Id"]
		if unit == "" {
			continue
		}
		m.seen[unit] = true
		active := props["ActiveState"] == "active"

		s := Service{
			ID: "systemd:" + unit, Kind: "systemd", Unit: unit,
			Name:        strings.TrimSuffix(unit, ".service"),
			Description: props["Description"],
			State:       props["ActiveState"], SubState: props["SubState"],
			Running: active, Enabled: props["UnitFileState"] == "enabled",
			Ports: []int{},
		}
		if name, ok := watched[unit]; ok {
			s.Watched, s.Name = true, name
		}
		if pid := parseInt(props["MainPID"]); pid != nil && *pid > 0 {
			p := int(*pid)
			s.PID = &p
		}
		if restarts := parseInt(props["NRestarts"]); restarts != nil {
			s.Restarts = int(*restarts)
		}
		if active {
			s.MemoryBytes = parseInt(props["MemoryCurrent"])
			if ns := parseInt(props["CPUUsageNSec"]); ns != nil {
				if prev, ok := m.cpuSamples[unit]; ok && now.After(prev.at) {
					pct := round1(float64(*ns-prev.ns) / 1e9 / now.Sub(prev.at).Seconds() * 100)
					if pct >= 0 {
						s.CPUPercent = &pct
					}
				}
				m.cpuSamples[unit] = cpuSample{now, *ns}
			}
			if usec := parseInt(props["ActiveEnterTimestampMonotonic"]); usec != nil && *usec > 0 && uptime > 0 {
				up := int64(uptime - float64(*usec)/1e6)
				if up >= 0 {
					s.Uptime = &up
				}
			}
			portSet := map[int]bool{}
			for _, pid := range cgroupPids(props["ControlGroup"]) {
				for _, port := range listen[pid] {
					portSet[port] = true
				}
			}
			for port := range portSet {
				s.Ports = append(s.Ports, port)
			}
			sort.Ints(s.Ports)
		}
		services = append(services, s)
	}
	return services
}

func parseSize(text string) *int64 {
	text = strings.TrimSpace(text)
	units := []struct {
		suffix string
		factor float64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"TiB", 1 << 40},
		{"kB", 1e3}, {"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12}, {"B", 1}}
	for _, u := range units {
		if strings.HasSuffix(text, u.suffix) {
			value, err := strconv.ParseFloat(strings.TrimSuffix(text, u.suffix), 64)
			if err != nil {
				return nil
			}
			n := int64(value * u.factor)
			return &n
		}
	}
	return nil
}

func dockerPorts(text string) []int {
	set := map[int]bool{}
	for _, mapping := range strings.Split(text, ", ") {
		hostPart, _, ok := strings.Cut(mapping, "->")
		if !ok {
			continue
		}
		port := hostPart[strings.LastIndex(hostPart, ":")+1:]
		port, _, _ = strings.Cut(port, "-")
		if n, err := strconv.Atoi(port); err == nil {
			set[n] = true
		}
	}
	ports := []int{}
	for port := range set {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func (m *ServiceManager) dockerServices() []Service {
	if !cfg.Services.Docker || !hasCommand("docker") {
		return nil
	}
	if m.dockerCache != nil && time.Since(m.dockerAt) < 5*time.Second {
		return m.dockerCache
	}
	ps, err := run(10*time.Second, "docker", "ps", "-a", "--format", "{{json .}}")
	if err != nil {
		return nil
	}
	statsOut, _ := run(15*time.Second, "docker", "stats", "--no-stream", "--format", "{{json .}}")
	type dockerStats struct{ Name, MemUsage, CPUPerc string }
	stats := map[string]dockerStats{}
	for _, line := range strings.Split(statsOut, "\n") {
		var s dockerStats
		if json.Unmarshal([]byte(line), &s) == nil && s.Name != "" {
			stats[s.Name] = s
		}
	}

	services := []Service{}
	for _, line := range strings.Split(ps, "\n") {
		var c struct{ Names, Image, State, Status, Ports string }
		if json.Unmarshal([]byte(line), &c) != nil || c.Names == "" {
			continue
		}
		name := c.Names
		running := c.State == "running"
		s := Service{
			ID: "docker:" + name, Kind: "docker", Name: name, Unit: c.Image,
			Description: c.Status, Watched: true, State: c.State, SubState: c.Status,
			Running: running, Enabled: true, Ports: dockerPorts(c.Ports),
		}
		if st, ok := stats[name]; ok && running {
			s.MemoryBytes = parseSize(strings.Split(st.MemUsage, "/")[0])
			if pct, err := strconv.ParseFloat(strings.TrimSuffix(st.CPUPerc, "%"), 64); err == nil {
				s.CPUPercent = &pct
			}
		}
		services = append(services, s)
	}
	m.dockerCache, m.dockerAt = services, time.Now()
	return services
}

func (m *ServiceManager) list() []Service {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listLocked()
}

func (m *ServiceManager) listLocked() []Service {
	services := []Service{}
	if hasCommand("systemctl") {
		services = append(services, m.systemdServices(listeningPorts())...)
	}
	services = append(services, m.dockerServices()...)
	sort.SliceStable(services, func(i, j int) bool {
		a, b := services[i], services[j]
		if a.Watched != b.Watched {
			return a.Watched
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return services
}

// resolve valida el ID contra los servicios conocidos: nunca se pasa a un
// comando un nombre que no haya salido de systemd o docker.
func (m *ServiceManager) resolve(id string) (kind, name string, err error) {
	kind, name, _ = strings.Cut(id, ":")
	switch kind {
	case "systemd":
		if len(m.seen) == 0 {
			m.listLocked()
		}
		if _, watched := m.watchedUnits()[name]; !watched && !m.seen[name] {
			return "", "", errors.New("Servicio no gestionado por Nido")
		}
	case "docker":
		found := false
		for _, s := range m.dockerServices() {
			found = found || s.Name == name
		}
		if !found {
			return "", "", errors.New("Contenedor no encontrado")
		}
	default:
		return "", "", errors.New("ID de servicio inválido")
	}
	return kind, name, nil
}

func (m *ServiceManager) action(id, action string) error {
	if !cfg.Services.AllowActions {
		return errors.New("Las acciones sobre servicios están desactivadas")
	}
	if action != "start" && action != "stop" && action != "restart" {
		return errors.New("Acción inválida")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	kind, name, err := m.resolve(id)
	if err != nil {
		return err
	}
	command := "systemctl"
	if kind == "docker" {
		command = "docker"
		m.dockerCache = nil
	}
	if out, err := run(60*time.Second, command, action, name); err != nil {
		if msg := strings.TrimSpace(out); msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}

func (m *ServiceManager) setWatched(id string, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kind, name, err := m.resolve(id)
	if err != nil {
		return err
	}
	if kind != "systemd" {
		return errors.New("Solo se pueden fijar servicios systemd")
	}
	m.store.setWatched(name, on)
	return nil
}

func (m *ServiceManager) logs(id string, lines int) ([]string, error) {
	lines = min(max(lines, 10), 500)
	m.mu.Lock()
	kind, name, err := m.resolve(id)
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var out string
	if kind == "systemd" {
		out, err = run(15*time.Second, "journalctl", "-u", name, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
	} else {
		out, err = run(15*time.Second, "docker", "logs", "--tail", strconv.Itoa(lines), name)
	}
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, errors.New("No se pudieron leer los logs")
	}
	all := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return all, nil
}
