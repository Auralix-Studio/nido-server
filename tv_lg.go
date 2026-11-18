package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Control de televisores LG webOS por la red local (protocolo SSAP).
//
// La primera conexión pide permiso en la pantalla de la TV; al aceptarlo, la
// TV entrega una clave que se guarda en secrets.yaml y sirve para las
// siguientes conexiones sin preguntar. Encender usa Wake-on-LAN: la TV debe
// tener activado "Encender con WiFi/LAN" (Ajustes > General > Dispositivos).

var tvPermissions = []string{
	"LAUNCH", "LAUNCH_WEBAPP", "APP_TO_APP", "CLOSE", "CONTROL_AUDIO", "CONTROL_DISPLAY",
	"CONTROL_INPUT_JOYSTICK", "CONTROL_INPUT_MEDIA_PLAYBACK", "CONTROL_INPUT_TV", "CONTROL_POWER",
	"CONTROL_INPUT_TEXT", "CONTROL_MOUSE_AND_KEYBOARD", "READ_APP_STATUS", "READ_CURRENT_CHANNEL",
	"READ_INPUT_DEVICE_LIST", "READ_NETWORK_STATE", "READ_RUNNING_APPS", "READ_TV_CHANNEL_LIST",
	"READ_INSTALLED_APPS", "READ_POWER_STATE", "WRITE_NOTIFICATION_TOAST",
}

var (
	errTVOffline   = errors.New("la TV no responde: está apagada o fuera de la red")
	errTVNotPaired = errors.New("la TV no está emparejada: pulsa pair() y acepta el aviso en la pantalla")
	errTVRejected  = errors.New("la TV rechazó el emparejamiento")
)

// Puertos de la TV; variables para poder probar contra una TV simulada.
var tvPorts = struct{ secure, plain int }{3001, 3000}

type tvMessage struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	URI     string          `json:"uri,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

type tvClient struct {
	host string
	conn *websocket.Conn
	next int
}

func dialTV(host string) (*tvClient, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: 4 * time.Second,
		// La TV usa un certificado auto-firmado
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	urls := []string{
		fmt.Sprintf("wss://%s:%d/", host, tvPorts.secure),
		fmt.Sprintf("ws://%s:%d/", host, tvPorts.plain),
	}
	var lastErr error
	for _, u := range urls {
		conn, _, err := dialer.Dial(u, nil)
		if err == nil {
			return &tvClient{host: host, conn: conn}, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("%w (%v)", errTVOffline, lastErr)
}

func (c *tvClient) close() { c.conn.Close() }

func (c *tvClient) send(msg tvMessage) error {
	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return c.conn.WriteJSON(msg)
}

func (c *tvClient) read(timeout time.Duration) (tvMessage, error) {
	var msg tvMessage
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	err := c.conn.ReadJSON(&msg)
	return msg, err
}

// register se identifica ante la TV. Con clave guardada es inmediato; sin
// ella (o si caducó) la TV muestra un aviso y se espera hasta waitPrompt.
func (c *tvClient) register(key string, waitPrompt time.Duration) (string, error) {
	manifest := map[string]any{
		"manifestVersion":      1,
		"appVersion":           "1.0",
		"permissions":          tvPermissions,
		"localizedAppNames":    map[string]string{"": "Nido"},
		"localizedVendorNames": map[string]string{"": "Auralix Studio"},
	}
	payload := map[string]any{"forcePairing": false, "pairingType": "PROMPT", "manifest": manifest}
	if key != "" {
		payload["client-key"] = key
	}
	raw, _ := json.Marshal(payload)
	if err := c.send(tvMessage{Type: "register", ID: "register_0", Payload: raw}); err != nil {
		return "", err
	}
	deadline := time.Now().Add(waitPrompt)
	for {
		remaining := time.Until(deadline)
		if remaining < 2*time.Second {
			remaining = 2 * time.Second
		}
		msg, err := c.read(remaining)
		if err != nil {
			if key == "" || time.Now().After(deadline) {
				return "", errTVNotPaired
			}
			return "", err
		}
		switch msg.Type {
		case "registered":
			var reply struct {
				Key string `json:"client-key"`
			}
			json.Unmarshal(msg.Payload, &reply)
			if reply.Key == "" {
				reply.Key = key
			}
			return reply.Key, nil
		case "error":
			return "", fmt.Errorf("%w: %s", errTVRejected, msg.Error)
		case "response":
			// {"pairingType":"PROMPT"}: la TV está mostrando el aviso
			if waitPrompt == 0 {
				return "", errTVNotPaired
			}
		}
	}
}

// call ejecuta una orden ssap:// y devuelve la respuesta de la TV.
func (c *tvClient) call(uri string, payload any) (map[string]any, error) {
	c.next++
	id := fmt.Sprintf("req_%d", c.next)
	msg := tvMessage{Type: "request", ID: id, URI: uri}
	if payload != nil {
		msg.Payload, _ = json.Marshal(payload)
	}
	if err := c.send(msg); err != nil {
		return nil, err
	}
	for {
		reply, err := c.read(8 * time.Second)
		if err != nil {
			return nil, err
		}
		if reply.ID != id {
			continue
		}
		if reply.Type == "error" {
			return nil, fmt.Errorf("la TV rechazó %s: %s", strings.TrimPrefix(uri, "ssap://"), reply.Error)
		}
		result := map[string]any{}
		json.Unmarshal(reply.Payload, &result)
		if ok, present := result["returnValue"].(bool); present && !ok {
			text, _ := result["errorText"].(string)
			return nil, fmt.Errorf("la TV rechazó %s: %s", strings.TrimPrefix(uri, "ssap://"), text)
		}
		return result, nil
	}
}

// button pulsa una tecla del mando (UP, DOWN, LEFT, RIGHT, ENTER, BACK, HOME...).
func (c *tvClient) button(name string) error {
	result, err := c.call("ssap://com.webos.service.networkinput/getPointerInputSocket", nil)
	if err != nil {
		return err
	}
	path, _ := result["socketPath"].(string)
	if path == "" {
		return errors.New("la TV no ofreció el canal del mando")
	}
	dialer := websocket.Dialer{HandshakeTimeout: 4 * time.Second,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	conn, _, err := dialer.Dial(path, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.WriteMessage(websocket.TextMessage, []byte("type:button\nname:"+name+"\n\n"))
}

// ---------- Wake-on-LAN ----------

func wakeOnLAN(mac string) error {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("MAC de la TV inválida: %q", mac)
	}
	packet := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		packet = append(packet, 0xff)
	}
	for i := 0; i < 16; i++ {
		packet = append(packet, hw...)
	}
	targets := []string{"255.255.255.255:9"}
	if info, err := detectNetwork(); err == nil {
		bcast := info.Prefix.Addr().As4()
		bits := info.Prefix.Bits()
		for i := 0; i < 4; i++ {
			for b := 0; b < 8; b++ {
				if i*8+b >= bits {
					bcast[i] |= 0x80 >> b
				}
			}
		}
		targets = append(targets, fmt.Sprintf("%d.%d.%d.%d:9", bcast[0], bcast[1], bcast[2], bcast[3]))
	}
	sent := false
	for _, target := range targets {
		addr, err := net.ResolveUDPAddr("udp4", target)
		if err != nil {
			continue
		}
		conn, err := net.DialUDP("udp4", nil, addr)
		if err != nil {
			continue
		}
		for i := 0; i < 3; i++ {
			if _, err := conn.Write(packet); err == nil {
				sent = true
			}
		}
		conn.Close()
	}
	if !sent {
		return errors.New("no se pudo enviar el paquete de encendido")
	}
	return nil
}

// ---------- gestor ----------

type TVManager struct {
	mu    sync.Mutex // la TV atiende mejor una conexión a la vez
	store *Store
}

// target devuelve IP y MAC de la TV: de la configuración o, si no, del
// dispositivo de la red cuyo nombre la delata como LG webOS.
func (m *TVManager) target() (host, mac string) {
	host, mac = cfg.TV.Host, normalizeMAC(cfg.TV.MAC)
	if host != "" && mac != "" {
		return host, mac
	}
	for _, d := range m.store.devices() {
		name := strings.ToLower(d.Hostname + " " + d.Name + " " + d.Vendor)
		if !strings.Contains(name, "webos") && !strings.Contains(name, "lgtv") && d.Tag != "tv" {
			continue
		}
		if host == "" {
			host = d.IP
		}
		if mac == "" {
			mac = d.MAC
		}
		break
	}
	return host, mac
}

// session conecta, se identifica con la clave guardada y ejecuta op.
func (m *TVManager) session(op func(*tvClient) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	host, _ := m.target()
	if host == "" {
		return errors.New("no se encontró ninguna TV LG en la red (ponle la etiqueta tv en la pestaña red)")
	}
	if secrets.TVClientKey == "" {
		return errTVNotPaired
	}
	client, err := dialTV(host)
	if err != nil {
		return err
	}
	defer client.close()
	if _, err := client.register(secrets.TVClientKey, 0); err != nil {
		return err
	}
	return op(client)
}

// pair pide permiso en la pantalla de la TV y guarda la clave.
func (m *TVManager) pair() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	host, _ := m.target()
	if host == "" {
		return errors.New("no se encontró ninguna TV LG en la red")
	}
	client, err := dialTV(host)
	if err != nil {
		return err
	}
	defer client.close()
	key, err := client.register(secrets.TVClientKey, 60*time.Second)
	if err != nil {
		return err
	}
	secrets.TVClientKey = key
	return saveSecrets()
}

func (m *TVManager) status() M {
	host, mac := m.target()
	status := M{"host": host, "mac": mac, "paired": secrets.TVClientKey != "", "online": false}
	if host == "" {
		return status
	}
	err := m.session(func(c *tvClient) error {
		status["online"] = true
		if r, err := c.call("ssap://audio/getVolume", nil); err == nil {
			status["volume"] = r["volume"]
			status["muted"] = r["muted"]
			if inner, ok := r["volumeStatus"].(map[string]any); ok { // webOS 5+
				status["volume"], status["muted"] = inner["volume"], inner["muteStatus"]
			}
		}
		if r, err := c.call("ssap://com.webos.applicationManager/getForegroundAppInfo", nil); err == nil {
			status["app"] = r["appId"]
		}
		return nil
	})
	if err != nil && !errors.Is(err, errTVOffline) {
		status["error"] = err.Error()
	}
	return status
}

func (m *TVManager) apps() ([]M, error) {
	var apps []M
	err := m.session(func(c *tvClient) error {
		r, err := c.call("ssap://com.webos.applicationManager/listLaunchPoints", nil)
		if err != nil {
			return err
		}
		list, _ := r["launchPoints"].([]any)
		for _, item := range list {
			if app, ok := item.(map[string]any); ok {
				apps = append(apps, M{"id": app["id"], "title": app["title"]})
			}
		}
		return nil
	})
	return apps, err
}

var tvButtons = map[string]bool{
	"UP": true, "DOWN": true, "LEFT": true, "RIGHT": true, "ENTER": true, "BACK": true,
	"HOME": true, "MENU": true, "EXIT": true, "INFO": true, "DASH": true,
}

// command ejecuta una orden del mando. value depende de la acción.
func (m *TVManager) command(action, value string) error {
	if action == "power_on" {
		_, mac := m.target()
		if mac == "" {
			return errors.New("no se conoce la MAC de la TV para encenderla")
		}
		return wakeOnLAN(mac)
	}
	calls := map[string]string{
		"power_off":    "ssap://system/turnOff",
		"volume_up":    "ssap://audio/volumeUp",
		"volume_down":  "ssap://audio/volumeDown",
		"channel_up":   "ssap://tv/channelUp",
		"channel_down": "ssap://tv/channelDown",
		"play":         "ssap://media.controls/play",
		"pause":        "ssap://media.controls/pause",
		"stop":         "ssap://media.controls/stop",
		"rewind":       "ssap://media.controls/rewind",
		"forward":      "ssap://media.controls/fastForward",
	}
	return m.session(func(c *tvClient) error {
		if uri, ok := calls[action]; ok {
			_, err := c.call(uri, nil)
			return err
		}
		switch action {
		case "mute":
			_, err := c.call("ssap://audio/setMute", M{"mute": value != "false"})
			return err
		case "volume_set":
			var level int
			if _, err := fmt.Sscan(value, &level); err != nil || level < 0 || level > 100 {
				return errors.New("volumen inválido (0-100)")
			}
			_, err := c.call("ssap://audio/setVolume", M{"volume": level})
			return err
		case "launch":
			if value == "" {
				return errors.New("falta la app")
			}
			_, err := c.call("ssap://system.launcher/launch", M{"id": value})
			return err
		case "toast":
			if value == "" {
				return errors.New("falta el mensaje")
			}
			_, err := c.call("ssap://system.notifications/createToast", M{"message": value})
			return err
		case "button":
			name := strings.ToUpper(value)
			if !tvButtons[name] {
				return fmt.Errorf("tecla desconocida: %s", value)
			}
			return c.button(name)
		}
		return fmt.Errorf("acción desconocida: %s", action)
	})
}
