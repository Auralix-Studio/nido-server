package main

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
)

type M = map[string]any

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// temperature lee el sensor más caliente de /sys (solo Linux).
func temperature() any {
	patterns := []string{"/sys/class/hwmon/hwmon*/temp*_input", "/sys/class/thermal/thermal_zone*/temp"}
	best := -1.0
	for _, pattern := range patterns {
		files, _ := filepath.Glob(pattern)
		for _, file := range files {
			raw, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			milli, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
			if err == nil && milli > 0 && milli/1000 > best && milli/1000 < 150 {
				best = milli / 1000
			}
		}
		if best >= 0 {
			break
		}
	}
	if best < 0 {
		return nil
	}
	return round1(best)
}

var netSample struct {
	sync.Mutex
	at     time.Time
	rx, tx uint64
}

func netRates() M {
	result := M{"rx_bytes_per_sec": 0, "tx_bytes_per_sec": 0, "rx_total": 0, "tx_total": 0}
	counters, err := psnet.IOCounters(false)
	if err != nil || len(counters) == 0 {
		return result
	}
	rx, tx := counters[0].BytesRecv, counters[0].BytesSent
	netSample.Lock()
	defer netSample.Unlock()
	now := time.Now()
	if !netSample.at.IsZero() && rx >= netSample.rx && tx >= netSample.tx {
		dt := math.Max(now.Sub(netSample.at).Seconds(), 0.001)
		result["rx_bytes_per_sec"] = int64(float64(rx-netSample.rx) / dt)
		result["tx_bytes_per_sec"] = int64(float64(tx-netSample.tx) / dt)
	}
	netSample.at, netSample.rx, netSample.tx = now, rx, tx
	result["rx_total"], result["tx_total"] = rx, tx
	return result
}

func hostDisks() []M {
	mounts := []struct{ path, label string }{
		{"/host/root", "/"},
		{"/host/home", "/home"},
	}
	var list []M
	seen := map[uint64]bool{}
	for _, m := range mounts {
		if _, err := os.Stat(m.path); err != nil {
			continue
		}
		usage, err := disk.Usage(m.path)
		if err != nil || usage.Total == 0 || seen[usage.Total] {
			continue
		}
		seen[usage.Total] = true
		list = append(list, M{
			"mount": m.label, "device": m.label, "fstype": usage.Fstype,
			"total": usage.Total, "used": usage.Used, "percent": round1(usage.UsedPercent),
		})
	}
	return list
}

func disks() []M {
	if list := hostDisks(); len(list) > 0 {
		return list
	}
	list := []M{}
	seen := map[string]bool{}
	partitions, _ := disk.Partitions(false)
	for _, p := range partitions {
		switch p.Fstype {
		case "squashfs", "tmpfs", "overlay", "devtmpfs":
			continue
		}
		if seen[p.Device] {
			continue
		}
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil || usage.Total == 0 {
			continue
		}
		seen[p.Device] = true
		list = append(list, M{
			"mount": p.Mountpoint, "device": p.Device, "fstype": p.Fstype,
			"total": usage.Total, "used": usage.Used, "percent": round1(usage.UsedPercent),
		})
	}
	return list
}

func hostOS() string {
	raw, err := os.ReadFile("/host/root/etc/os-release")
	if err != nil {
		return ""
	}
	vals := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			vals[k] = strings.Trim(v, `"`)
		}
	}
	if vals["ID"] != "" && vals["VERSION_ID"] != "" {
		return vals["ID"] + " " + vals["VERSION_ID"]
	}
	return vals["PRETTY_NAME"]
}

func serverStatus() M {
	status := M{"hostname": "", "os": "", "uptime_seconds": 0}
	if info, err := host.Info(); err == nil {
		status["hostname"] = info.Hostname
		status["os"] = strings.TrimSpace(info.Platform + " " + info.PlatformVersion)
		status["uptime_seconds"] = info.Uptime
	}
	if osName := hostOS(); osName != "" {
		status["os"] = osName
	}

	cpuInfo := M{"percent": 0.0, "cores": 0, "load_avg": nil, "temperature": temperature()}
	if percent, err := cpu.Percent(300*time.Millisecond, false); err == nil && len(percent) > 0 {
		cpuInfo["percent"] = round1(percent[0])
	}
	if cores, err := cpu.Counts(true); err == nil {
		cpuInfo["cores"] = cores
	}
	if avg, err := load.Avg(); err == nil && (avg.Load1 > 0 || avg.Load5 > 0) {
		cpuInfo["load_avg"] = []float64{
			math.Round(avg.Load1*100) / 100, math.Round(avg.Load5*100) / 100, math.Round(avg.Load15*100) / 100,
		}
	}
	status["cpu"] = cpuInfo

	memory := M{"total": 0, "used": 0, "percent": 0.0, "swap_percent": 0.0}
	if vm, err := mem.VirtualMemory(); err == nil {
		memory["total"] = vm.Total
		memory["used"] = vm.Total - vm.Available
		memory["percent"] = round1(vm.UsedPercent)
	}
	if swap, err := mem.SwapMemory(); err == nil {
		memory["swap_percent"] = round1(swap.UsedPercent)
	}
	status["memory"] = memory
	status["disks"] = disks()
	status["network"] = netRates()
	return status
}
