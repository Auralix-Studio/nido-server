package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeTV imita una LG webOS: emparejamiento con aviso, órdenes ssap:// y el
// canal del mando (pointer input socket).
type fakeTV struct {
	mu       sync.Mutex
	key      string
	accept   bool // el usuario acepta el aviso en pantalla
	volume   int
	muted    bool
	launched string
	buttons  []string
	calls    []string
	server   *httptest.Server
}

func (f *fakeTV) serve(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	if r.URL.Path == "/pointer" {
		_, data, err := conn.ReadMessage()
		if err == nil {
			f.mu.Lock()
			f.buttons = append(f.buttons, string(data))
			f.mu.Unlock()
		}
		return
	}
	registered := false
	for {
		var msg tvMessage
		if conn.ReadJSON(&msg) != nil {
			return
		}
		reply := func(typ string, payload any, errText string) {
			raw, _ := json.Marshal(payload)
			conn.WriteJSON(tvMessage{Type: typ, ID: msg.ID, Payload: raw, Error: errText})
		}
		if msg.Type == "register" {
			var p map[string]any
			json.Unmarshal(msg.Payload, &p)
			f.mu.Lock()
			key, accept := f.key, f.accept
			f.mu.Unlock()
			if given, _ := p["client-key"].(string); given != "" && given == key {
				registered = true
				reply("registered", map[string]string{"client-key": key}, "")
				continue
			}
			reply("response", map[string]string{"pairingType": "PROMPT"}, "")
			if !accept {
				continue // sin respuesta: el aviso sigue en pantalla
			}
			f.mu.Lock()
			f.key = "clave-de-la-tv"
			f.mu.Unlock()
			registered = true
			reply("registered", map[string]string{"client-key": "clave-de-la-tv"}, "")
			continue
		}
		if !registered {
			reply("error", nil, "401 insufficient permissions (not registered)")
			continue
		}
		f.mu.Lock()
		f.calls = append(f.calls, msg.URI)
		var p map[string]any
		json.Unmarshal(msg.Payload, &p)
		switch msg.URI {
		case "ssap://audio/getVolume":
			f.mu.Unlock()
			reply("response", map[string]any{"returnValue": true, "volumeStatus": map[string]any{"volume": f.volume, "muteStatus": f.muted}}, "")
			continue
		case "ssap://audio/setVolume":
			f.volume = int(p["volume"].(float64))
		case "ssap://audio/volumeUp":
			f.volume++
		case "ssap://audio/setMute":
			f.muted = p["mute"].(bool)
		case "ssap://system.launcher/launch":
			f.launched = p["id"].(string)
		case "ssap://com.webos.applicationManager/listLaunchPoints":
			f.mu.Unlock()
			reply("response", map[string]any{"returnValue": true, "launchPoints": []any{
				map[string]any{"id": "youtube.leanback.v4", "title": "YouTube"},
				map[string]any{"id": "netflix", "title": "Netflix"},
			}}, "")
			continue
		case "ssap://com.webos.service.networkinput/getPointerInputSocket":
			f.mu.Unlock()
			reply("response", map[string]any{"returnValue": true,
				"socketPath": "ws" + strings.TrimPrefix(f.server.URL, "http") + "/pointer"}, "")
			continue
		case "ssap://system/turnOff":
		default:
			f.mu.Unlock()
			reply("response", map[string]any{"returnValue": false, "errorText": "unknown uri"}, "")
			continue
		}
		f.mu.Unlock()
		reply("response", map[string]any{"returnValue": true}, "")
	}
}

func newFakeTV(t *testing.T) (*fakeTV, *TVManager) {
	fake := &fakeTV{accept: true, volume: 10}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(fake.server.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(fake.server.URL, "http://"))
	plain, _ := strconv.Atoi(port)
	oldPorts, oldTV, oldKey := tvPorts, cfg.TV, secrets.TVClientKey
	t.Cleanup(func() { tvPorts, cfg.TV, secrets.TVClientKey = oldPorts, oldTV, oldKey })
	tvPorts.secure, tvPorts.plain = 1, plain // el seguro falla y usa el normal
	cfg.TV.Host, cfg.TV.MAC = host, "02:aa:bb:cc:dd:ee"
	secrets.TVClientKey = ""
	configPath = filepath.Join(t.TempDir(), "config.yaml")
	return fake, &TVManager{store: openStore(filepath.Join(t.TempDir(), "state.json"))}
}

func TestTVPairAndControl(t *testing.T) {
	fake, tv := newFakeTV(t)

	if err := tv.command("volume_up", ""); !errors.Is(err, errTVNotPaired) {
		t.Fatalf("sin emparejar debería pedir pair(): %v", err)
	}
	if err := tv.pair(); err != nil {
		t.Fatal(err)
	}
	if secrets.TVClientKey != "clave-de-la-tv" {
		t.Fatalf("clave guardada = %q", secrets.TVClientKey)
	}

	for _, step := range []struct{ action, value string }{
		{"volume_set", "25"}, {"volume_up", ""}, {"mute", "true"},
		{"launch", "youtube.leanback.v4"}, {"button", "enter"}, {"power_off", ""},
	} {
		if err := tv.command(step.action, step.value); err != nil {
			t.Fatalf("%s: %v", step.action, err)
		}
	}
	time.Sleep(50 * time.Millisecond) // el canal del mando se procesa aparte
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.volume != 26 || !fake.muted || fake.launched != "youtube.leanback.v4" {
		t.Errorf("estado TV: volumen %d, silencio %v, app %q", fake.volume, fake.muted, fake.launched)
	}
	if len(fake.buttons) != 1 || fake.buttons[0] != "type:button\nname:ENTER\n\n" {
		t.Errorf("teclas = %q", fake.buttons)
	}
}

func TestTVStatusAndApps(t *testing.T) {
	_, tv := newFakeTV(t)
	if err := tv.pair(); err != nil {
		t.Fatal(err)
	}
	status := tv.status()
	if status["online"] != true || status["paired"] != true || status["volume"] != float64(10) {
		t.Errorf("estado = %v", status)
	}
	apps, err := tv.apps()
	if err != nil || len(apps) != 2 || apps[0]["title"] != "YouTube" {
		t.Errorf("apps = %v, %v", apps, err)
	}
}

func TestTVRejectsBadInput(t *testing.T) {
	_, tv := newFakeTV(t)
	tv.pair()
	for _, step := range []struct{ action, value string }{
		{"volume_set", "500"}, {"button", "rm -rf"}, {"launch", ""}, {"hack", ""},
	} {
		if err := tv.command(step.action, step.value); err == nil {
			t.Errorf("%s %q debería rechazarse", step.action, step.value)
		}
	}
}

func TestTVOffline(t *testing.T) {
	_, tv := newFakeTV(t)
	secrets.TVClientKey = "x"
	tvPorts.secure, tvPorts.plain = 1, 2 // nada escuchando
	if status := tv.status(); status["online"] != false || status["error"] != nil {
		t.Errorf("TV apagada: %v", status)
	}
}

func TestWakeOnLANPacket(t *testing.T) {
	if err := wakeOnLAN("no-es-mac"); err == nil {
		t.Error("MAC inválida aceptada")
	}
}
