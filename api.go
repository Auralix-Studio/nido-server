package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type App struct {
	tv       *TVManager
	store    *Store
	services *ServiceManager
	scanner  *NetworkScanner
	scanNow  chan struct{}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func fail(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, M{"detail": detail})
}

var ok = M{"status": "ok"}

func readBody(w http.ResponseWriter, r *http.Request, into any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		fail(w, http.StatusBadRequest, "Cuerpo JSON inválido")
		return false
	}
	return true
}

func clientIP(r *http.Request) string {
	ip, _ := clientOrigin(r)
	return ip
}

// clientOrigin devuelve la IP del cliente y si llega desde internet. El túnel
// de Cloudflare se conecta por loopback y trae la IP real en CF-Connecting-IP;
// a un equipo de la LAN esa cabecera se le ignora, así que no puede falsearla.
func clientOrigin(r *http.Request) (ip string, remote bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if peer := net.ParseIP(host); peer != nil && peer.IsLoopback() {
		if real := net.ParseIP(r.Header.Get("CF-Connecting-IP")); real != nil {
			return real.String(), true
		}
	}
	return host, false
}

func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found || !verifyToken(token) {
			fail(w, http.StatusUnauthorized, "Token inválido o expirado")
			return
		}
		next(w, r)
	}
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, r *http.Request) {
		hostname, _ := os.Hostname()
		writeJSON(w, 200, M{"status": "alive", "service": "nido", "hostname": hostname})
	})
	mux.HandleFunc("POST /auth/login", a.login)
	mux.HandleFunc("GET /auth/verify", auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, M{"valid": true})
	}))

	// servidor
	mux.HandleFunc("GET /server/status", auth(func(w http.ResponseWriter, r *http.Request) {
		status := serverStatus()
		status["allow_power"] = cfg.Server.AllowPower
		_, status["unread_events"] = a.store.events(0)
		writeJSON(w, 200, status)
	}))
	mux.HandleFunc("POST /server/reboot", auth(func(w http.ResponseWriter, r *http.Request) { a.power(w, "reboot") }))
	mux.HandleFunc("POST /server/shutdown", auth(func(w http.ResponseWriter, r *http.Request) { a.power(w, "shutdown") }))

	// servicios
	mux.HandleFunc("GET /services", auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, M{"allow_actions": cfg.Services.AllowActions, "services": a.services.list()})
	}))
	mux.HandleFunc("POST /services/action", auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ ID, Action string }
		if !readBody(w, r, &body) {
			return
		}
		if err := a.services.action(body.ID, body.Action); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("Acción %s sobre %s", body.Action, body.ID)
		writeJSON(w, 200, M{"status": "ok", "id": body.ID, "action": body.Action})
	}))
	mux.HandleFunc("POST /services/watch", auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID      string
			Watched bool
		}
		if !readBody(w, r, &body) {
			return
		}
		if err := a.services.setWatched(body.ID, body.Watched); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, 200, ok)
	}))
	mux.HandleFunc("GET /services/logs", auth(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
		if lines == 0 {
			lines = 100
		}
		out, err := a.services.logs(id, lines)
		if err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, 200, M{"id": id, "lines": out})
	}))

	// red
	mux.HandleFunc("GET /network/devices", auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, a.scanner.snapshot())
	}))
	mux.HandleFunc("POST /network/scan", auth(func(w http.ResponseWriter, r *http.Request) {
		select {
		case a.scanNow <- struct{}{}:
		default: // ya hay uno pedido
		}
		writeJSON(w, 200, ok)
	}))
	mux.HandleFunc("POST /network/known-all", auth(func(w http.ResponseWriter, r *http.Request) {
		a.store.markAllKnown()
		writeJSON(w, 200, ok)
	}))
	mux.HandleFunc("PATCH /network/devices/{mac}", auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name  *string
			Tag   *string
			Known *bool
		}
		if !readBody(w, r, &body) {
			return
		}
		device, found := a.store.updateDevice(strings.ToLower(r.PathValue("mac")), body.Name, body.Tag, body.Known)
		if !found {
			fail(w, http.StatusNotFound, "Dispositivo no encontrado")
			return
		}
		writeJSON(w, 200, device)
	}))
	mux.HandleFunc("POST /network/devices/{mac}/block", auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Blocked bool }
		if !readBody(w, r, &body) {
			return
		}
		mac := strings.ToLower(r.PathValue("mac"))
		device, found := a.store.device(mac)
		if !found {
			fail(w, http.StatusNotFound, "Dispositivo no encontrado")
			return
		}
		if body.Blocked {
			if reason := a.blockRefusal(device, clientIP(r)); reason != "" {
				fail(w, http.StatusBadRequest, reason)
				return
			}
		}
		if err := a.scanner.setBlocked(mac, body.Blocked); err != nil {
			fail(w, http.StatusBadGateway, err.Error())
			return
		}
		label := device.Name
		if label == "" {
			label = device.Hostname
		}
		if label == "" {
			label = mac
		}
		action := "desbloqueado"
		if body.Blocked {
			action = "bloqueado"
		}
		a.notify("block", fmt.Sprintf("Dispositivo %s: %s", action, label), mac, false)
		writeJSON(w, 200, M{"status": "ok", "blocked": body.Blocked})
	}))
	mux.HandleFunc("DELETE /network/devices/{mac}", auth(func(w http.ResponseWriter, r *http.Request) {
		a.store.deleteDevice(strings.ToLower(r.PathValue("mac")))
		writeJSON(w, 200, ok)
	}))

	// TV
	mux.HandleFunc("GET /tv/status", auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, a.tv.status())
	}))
	mux.HandleFunc("POST /tv/pair", auth(func(w http.ResponseWriter, r *http.Request) {
		if err := a.tv.pair(); err != nil {
			fail(w, http.StatusBadGateway, err.Error())
			return
		}
		a.notify("tv", "TV emparejada con Nido", "", false)
		writeJSON(w, 200, ok)
	}))
	mux.HandleFunc("GET /tv/apps", auth(func(w http.ResponseWriter, r *http.Request) {
		apps, err := a.tv.apps()
		if err != nil {
			fail(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, 200, M{"apps": apps})
	}))
	mux.HandleFunc("POST /tv/command", auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Action, Value string }
		if !readBody(w, r, &body) {
			return
		}
		if err := a.tv.command(body.Action, body.Value); err != nil {
			fail(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, 200, ok)
	}))

	// eventos
	mux.HandleFunc("GET /events", auth(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 100
		}
		events, unread := a.store.events(min(limit, maxEvents))
		writeJSON(w, 200, M{"unread": unread, "events": events})
	}))
	mux.HandleFunc("POST /events/read", auth(func(w http.ResponseWriter, r *http.Request) {
		a.store.markEventsRead()
		writeJSON(w, 200, ok)
	}))
	return mux
}

// blockRefusal devuelve por qué no se debe bloquear un dispositivo, o "".
func (a *App) blockRefusal(device Device, requesterIP string) string {
	snapshot := a.scanner.snapshot()
	switch {
	case device.IP != "" && device.IP == snapshot["server_ip"]:
		return "No se puede bloquear el propio servidor"
	case device.IP != "" && device.IP == snapshot["gateway"]:
		return "No se puede bloquear el router"
	case device.IP != "" && device.IP == requesterIP:
		return "Ese es el dispositivo que estás usando ahora"
	case device.Conn == "eth":
		return "El router solo permite bloquear dispositivos WiFi"
	}
	return ""
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var body struct{ Pin string }
	if !readBody(w, r, &body) {
		return
	}
	ip, remote := clientOrigin(r)
	if remaining := limiter.lockedFor(ip); remaining > 0 {
		fail(w, http.StatusTooManyRequests, fmt.Sprintf("Esperar %ds", remaining))
		return
	}
	if remote {
		if remaining := limiter.remoteLockedFor(); remaining > 0 {
			fail(w, http.StatusTooManyRequests, fmt.Sprintf("Acceso externo en pausa %d min", remaining/60+1))
			return
		}
	}
	success := verifyPin(body.Pin)
	if remote && limiter.registerRemote(success) {
		a.notify("auth", "Acceso externo en pausa: demasiados PIN fallidos desde internet", "", true)
	}
	if limiter.register(ip, success) {
		a.notify("auth", "Demasiados intentos de PIN fallidos desde "+ip, "", true)
		fail(w, http.StatusTooManyRequests, "Bloqueado")
		return
	}
	if !success {
		fail(w, http.StatusUnauthorized, "PIN incorrecto")
		return
	}
	log.Printf("Login correcto desde %s", ip)
	writeJSON(w, 200, M{"token": createToken(ip), "expires_in_hours": cfg.Auth.JWTExpiryHours})
}

func (a *App) power(w http.ResponseWriter, action string) {
	if !cfg.Server.AllowPower {
		fail(w, http.StatusForbidden, "Apagado/reinicio desactivado en config")
		return
	}
	command, label := []string{"systemctl", "poweroff"}, "apagado"
	if action == "reboot" {
		command, label = []string{"systemctl", "reboot"}, "reinicio"
	}
	if isWindows {
		flag := map[string]string{"reboot": "/r", "shutdown": "/s"}[action]
		command = []string{"shutdown", flag, "/t", "5"}
	}
	a.notify("power", "Orden de "+label+" desde la app", "", false)
	time.AfterFunc(time.Second, func() { exec.Command(command[0], command[1:]...).Run() })
	writeJSON(w, 200, M{"status": "ok", "action": action})
}
