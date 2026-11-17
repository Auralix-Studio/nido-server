package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Device struct {
	MAC       string  `json:"mac"`
	IP        string  `json:"ip"`
	Hostname  string  `json:"hostname"`
	Vendor    string  `json:"vendor"`
	Name      string  `json:"name"`
	Tag       string  `json:"tag"`
	Conn      string  `json:"conn"` // "wifi", "eth" o "" si no se sabe
	SSID      string  `json:"ssid"`
	Port      string  `json:"port"`
	Signal    int     `json:"signal"` // RSSI en dBm; 0 = desconocido
	Known     bool    `json:"known"`
	Blocked   bool    `json:"blocked"` // con regla en el filtro MAC del router
	FirstSeen float64 `json:"first_seen"`
	LastSeen  float64 `json:"last_seen"`
}

type Event struct {
	ID      int     `json:"id"`
	TS      float64 `json:"ts"`
	Type    string  `json:"type"`
	MAC     string  `json:"mac"`
	Message string  `json:"message"`
	Read    int     `json:"read"`
}

type state struct {
	Devices     map[string]*Device `json:"devices"`
	Events      []Event            `json:"events"` // más reciente primero
	NextEventID int                `json:"next_event_id"`
	Watched     []string           `json:"watched"`
}

// Store guarda el estado en un único archivo JSON (son pocos datos).
type Store struct {
	mu   sync.Mutex
	path string
	s    state
}

const maxEvents = 500

func nowTS() float64 { return float64(time.Now().UnixMilli()) / 1000 }

func openStore(path string) *Store {
	st := &Store{path: path, s: state{Devices: map[string]*Device{}, NextEventID: 1}}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &st.s); err != nil {
			log.Fatalf("%s está dañado: %v", path, err)
		}
		if st.s.Devices == nil {
			st.s.Devices = map[string]*Device{}
		}
	}
	return st
}

// save escribe de forma atómica. Debe llamarse con el mutex tomado.
func (st *Store) save() {
	data, err := json.Marshal(&st.s)
	if err == nil {
		err = os.MkdirAll(filepath.Dir(st.path), 0o755)
	}
	if err == nil {
		tmp := st.path + ".tmp"
		if err = os.WriteFile(tmp, data, 0o600); err == nil {
			err = os.Rename(tmp, st.path)
		}
	}
	if err != nil {
		log.Printf("No se pudo guardar el estado: %v", err)
	}
}

// ---------- dispositivos ----------

type seenDevice struct {
	MAC, IP, Hostname, Vendor, Conn string
	SSID, Port                      string
	Signal                          int
}

// markSeen registra los dispositivos presentes y devuelve los que son nuevos.
func (st *Store) markSeen(found []seenDevice) []Device {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := nowTS()
	var fresh []Device
	for _, f := range found {
		d, ok := st.s.Devices[f.MAC]
		if !ok {
			d = &Device{MAC: f.MAC, FirstSeen: now}
			st.s.Devices[f.MAC] = d
		}
		d.LastSeen = now
		if f.IP != "" {
			d.IP = f.IP
		}
		if f.Hostname != "" {
			d.Hostname = f.Hostname
		}
		if f.Vendor != "" {
			d.Vendor = f.Vendor
		}
		if f.Conn != "" {
			d.Conn, d.SSID, d.Port, d.Signal = f.Conn, f.SSID, f.Port, f.Signal
		}
		if !ok {
			fresh = append(fresh, *d)
		}
	}
	st.save()
	return fresh
}

func (st *Store) devices() []Device {
	st.mu.Lock()
	defer st.mu.Unlock()
	list := make([]Device, 0, len(st.s.Devices))
	for _, d := range st.s.Devices {
		list = append(list, *d)
	}
	return list
}

func (st *Store) deviceCount() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.s.Devices)
}

// updateDevice aplica los cambios y devuelve el dispositivo, o false si no existe.
func (st *Store) updateDevice(mac string, name, tag *string, known *bool) (Device, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	d, ok := st.s.Devices[mac]
	if !ok {
		return Device{}, false
	}
	if name != nil {
		d.Name = *name
	}
	if tag != nil {
		d.Tag = *tag
	}
	if known != nil {
		d.Known = *known
	}
	st.save()
	return *d, true
}

// syncBlocked deja marcados como bloqueados exactamente los de la lista.
func (st *Store) syncBlocked(macs []string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	blocked := map[string]bool{}
	for _, mac := range macs {
		blocked[mac] = true
	}
	changed := false
	for mac, d := range st.s.Devices {
		if d.Blocked != blocked[mac] {
			d.Blocked, changed = blocked[mac], true
		}
	}
	if changed {
		st.save()
	}
}

func (st *Store) device(mac string) (Device, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	d, ok := st.s.Devices[mac]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

func (st *Store) setBlocked(mac string, blocked bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if d, ok := st.s.Devices[mac]; ok {
		d.Blocked = blocked
		st.save()
	}
}

func (st *Store) markAllKnown() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, d := range st.s.Devices {
		d.Known = true
	}
	st.save()
}

func (st *Store) deleteDevice(mac string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.s.Devices, mac)
	st.save()
}

// ---------- servicios fijados ----------

func (st *Store) watched() []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]string(nil), st.s.Watched...)
}

func (st *Store) setWatched(unit string, on bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	kept := st.s.Watched[:0]
	for _, u := range st.s.Watched {
		if u != unit {
			kept = append(kept, u)
		}
	}
	if on {
		kept = append(kept, unit)
		sort.Strings(kept)
	}
	st.s.Watched = kept
	st.save()
}

// ---------- eventos ----------

func (st *Store) addEvent(typ, message, mac string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	event := Event{ID: st.s.NextEventID, TS: nowTS(), Type: typ, MAC: mac, Message: message}
	st.s.NextEventID++
	st.s.Events = append([]Event{event}, st.s.Events...)
	if len(st.s.Events) > maxEvents {
		st.s.Events = st.s.Events[:maxEvents]
	}
	st.save()
}

func (st *Store) events(limit int) ([]Event, int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	unread := 0
	for _, e := range st.s.Events {
		if e.Read == 0 {
			unread++
		}
	}
	if limit > len(st.s.Events) {
		limit = len(st.s.Events)
	}
	return append([]Event{}, st.s.Events[:limit]...), unread
}

func (st *Store) markEventsRead() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for i := range st.s.Events {
		st.s.Events[i].Read = 1
	}
	st.save()
}
