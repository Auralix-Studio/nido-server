package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Cliente del panel web de routers ZTE (F6600P y similares).
//
// Cada consulta inicia sesión, lee la lista de equipos y cierra sesión: el
// router solo admite un administrador conectado a la vez, así no te deja
// fuera del panel cuando quieras entrar tú.

type routerDevice struct {
	MAC, IP, Hostname, Conn string
	SSID                    string // red WiFi a la que está asociado
	Port                    string // puerto físico (LAN1..LAN4) si va por cable
	Signal                  int    // RSSI en dBm; 0 = desconocido
	LinkSeconds             int    // tiempo conectado al WiFi
}

// routerStatus es el estado del propio router.
type routerStatus struct {
	Model    string  `json:"model"`
	Firmware string  `json:"firmware"`
	CPU      float64 `json:"cpu_percent"`
	Memory   float64 `json:"memory_percent"`
	Temp     float64 `json:"temperature"`
	Uptime   int     `json:"uptime_seconds"`
}

type zteClient struct {
	base     string
	username string
	password string
	http     *http.Client
	token    string            // token de sesión tras el login
	raw      map[string]string // respuestas crudas, para --router-test
	info     *routerStatus     // estado del router leído en la última consulta
	pubKey   *rsa.PublicKey    // clave con la que se firman los cambios
	blocked  []string          // MAC con regla de bloqueo; nil = no se pudo leer
	force    bool              // expulsar también sesiones de otras personas
	moved    []string          // bloqueos movidos a otra banda en la última lectura
}

func newZTEClient(base, username, password string) *zteClient {
	jar, _ := cookiejar.New(nil)
	return &zteClient{
		base: strings.TrimRight(base, "/"), username: username, password: password,
		http: &http.Client{Jar: jar, Timeout: 10 * time.Second},
		raw:  map[string]string{},
	}
}

func (z *zteClient) request(method, query string, form url.Values) ([]byte, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, z.base+"/"+query, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Referer", z.base+"/")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	resp, err := z.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

type zteLoginReply struct {
	SessToken   string `json:"sess_token"`
	LockingTime int    `json:"lockingTime"`
	LoginErrMsg string `json:"loginErrMsg"`
	NeedRefresh bool   `json:"login_need_refresh"`
}

// errRouterAuth indica credenciales rechazadas: no hay que reintentar en bucle
// porque el router bloquea el acceso tras varios fallos.
var errRouterAuth = errors.New("el router rechazó el usuario o la contraseña")

func (z *zteClient) login() error {
	if _, err := z.request("GET", "", nil); err != nil { // cookie de sesión
		return fmt.Errorf("router inaccesible: %w", err)
	}
	raw, err := z.request("GET", "?_type=loginData&_tag=login_entry", nil)
	if err != nil {
		return err
	}
	var entry zteLoginReply
	if err := json.Unmarshal(raw, &entry); err != nil {
		return errors.New("el router no respondió como un ZTE compatible")
	}
	if entry.LockingTime > 0 {
		return fmt.Errorf("el router tiene el acceso bloqueado %d s por intentos fallidos", entry.LockingTime)
	}

	raw, err = z.request("GET", "?_type=loginData&_tag=login_token", nil)
	if err != nil {
		return err
	}
	var loginToken string
	if err := xml.Unmarshal(raw, &loginToken); err != nil || loginToken == "" {
		return errors.New("no se pudo obtener el token de login del router")
	}

	digest := sha256.Sum256([]byte(z.password + loginToken))
	raw, err = z.request("POST", "?_type=loginData&_tag=login_entry", url.Values{
		"action":        {"login"},
		"Password":      {hex.EncodeToString(digest[:])},
		"Username":      {z.username},
		"_sessionTOKEN": {entry.SessToken},
	})
	if err != nil {
		return err
	}
	var reply zteLoginReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return errors.New("respuesta de login inesperada del router")
	}
	if !reply.NeedRefresh {
		if reply.LockingTime > 0 {
			return fmt.Errorf("%w (bloqueado %d s)", errRouterAuth, reply.LockingTime)
		}
		if reply.LoginErrMsg != "" {
			return fmt.Errorf("%w: %s", errRouterAuth, reply.LoginErrMsg)
		}
		return errRouterAuth
	}
	z.token = reply.SessToken
	return z.resolvePreempt()
}

// Con otra sesión de administrador abierta, el router acepta el login pero
// muestra "Otro usuario está configurando el dispositivo" y responde
// SessionTimeout a todo hasta que se expulsa a la otra sesión.
var (
	rePreemptSession = regexp.MustCompile(`name="preempt_sessid" value="?([0-9a-fA-F]+)"?[^>]*/?>\s*<label[^>]*>([^<]*)</label>`)
	errRouterBusy    = errors.New("otra persona está usando el panel del router")
)

type preemptSession struct{ ID, Owner string }

func (z *zteClient) resolvePreempt() error {
	page, err := z.request("GET", "", nil)
	if err != nil || !strings.Contains(string(page), "login_preempt") {
		return err
	}
	var sessions []preemptSession
	for _, match := range rePreemptSession.FindAllStringSubmatch(string(page), -1) {
		sessions = append(sessions, preemptSession{ID: match[1], Owner: html.UnescapeString(match[2])})
	}
	if len(sessions) == 0 {
		return errors.New("el router pide expulsar otra sesión pero no se pudo leer cuál")
	}
	// Una sesión abierta desde esta misma máquina es nuestra y se quedó
	// colgada: se expulsa siempre. La de otra persona solo si se pide.
	self := localIP()
	for _, s := range sessions {
		mine := self != "" && strings.HasPrefix(s.Owner, self+"(")
		if !mine && !z.force {
			return fmt.Errorf("%w (%s)", errRouterBusy, s.Owner)
		}
	}
	raw, err := z.request("POST", "?_type=loginData&_tag=login_preempt", url.Values{
		"preempt_sessid": {sessions[0].ID}, "action": {"preempt"},
	})
	if err != nil {
		return err
	}
	var reply zteLoginReply
	if json.Unmarshal(raw, &reply) != nil || !reply.NeedRefresh {
		return errors.New("el router no aceptó expulsar la otra sesión")
	}
	if reply.SessToken != "" {
		z.token = reply.SessToken
	}
	log.Printf("Router: expulsada la sesión de %s", sessions[0].Owner)
	return nil
}

func (z *zteClient) logout() {
	z.request("POST", "?_type=loginData&_tag=logout_entry", url.Values{
		"IF_LogOff": {"1"}, "_sessionTOKEN": {z.token},
	})
}

// decodeValue descifra los valores que el router marca como "encode":
// AES-CBC con clave SHA256(token) e IV SHA256(token invertido), relleno de ceros.
func (z *zteClient) decodeValue(value string) string {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return value
	}
	runes := []rune(z.token)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	key := sha256.Sum256([]byte(z.token))
	iv := sha256.Sum256([]byte(string(runes)))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return value
	}
	cipher.NewCBCDecrypter(block, iv[:aes.BlockSize]).CryptBlocks(data, data)
	return strings.TrimRight(string(data), "\x00")
}

type zteInstance struct {
	Names  []string `xml:"ParaName"`
	Values []string `xml:"ParaValue"`
}

// parseInstances extrae cada <Instance> como mapa nombre -> valor.
func (z *zteClient) parseInstances(raw []byte) (instances []map[string]string, errStr string) {
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	decoder.Strict = false
	encoded := ""
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "IF_ERRORSTR":
			decoder.DecodeElement(&errStr, &start)
		case "encode":
			var text string
			decoder.DecodeElement(&text, &start)
			encoded += "," + text
		case "Instance":
			var inst zteInstance
			if decoder.DecodeElement(&inst, &start) != nil {
				continue
			}
			values := map[string]string{}
			for i, name := range inst.Names {
				if i < len(inst.Values) {
					// Algunos firmwares anteponen "_LuQUID_" a cada nombre
					values[strings.TrimPrefix(name, "_LuQUID_")] = inst.Values[i]
				}
			}
			instances = append(instances, values)
		}
	}
	for _, values := range instances {
		for name, value := range values {
			if strings.Contains(encoded, name) {
				values[name] = z.decodeValue(value)
			}
		}
	}
	return instances, errStr
}

func firstValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(values[key]); v != "" {
			return v
		}
	}
	return ""
}

func (z *zteClient) fetch(label, query, conn string) ([]routerDevice, error) {
	raw, err := z.request("GET", query, nil)
	if err != nil {
		return nil, err
	}
	z.raw[label] = string(raw)
	instances, errStr := z.parseInstances(raw)
	if errStr != "" && errStr != "SUCC" {
		return nil, fmt.Errorf("el router devolvió %s", errStr)
	}
	var devices []routerDevice
	for _, values := range instances {
		mac := normalizeMAC(firstValue(values, "MACAddress", "MACAddr", "MAC"))
		ip := firstValue(values, "IPAddress", "IPAddr", "IP")
		// Equipos asociados al WiFi pero aún sin IP llegan con 0.0.0.0 o 255.255.255.255
		if ip == "0.0.0.0" || ip == "255.255.255.255" {
			ip = ""
		}
		if mac == "" || (ip == "" && conn != "wifi") {
			continue
		}
		device := routerDevice{MAC: mac, IP: ip, Conn: conn, Hostname: firstValue(values, "HostName", "DevName")}
		switch conn {
		case "wifi":
			device.SSID = values["SSIDName"]
			device.Signal, _ = strconv.Atoi(values["RSSI"])
			device.LinkSeconds, _ = strconv.Atoi(values["LinkTime"])
		case "eth":
			device.Port = values["AliasName"]
		}
		devices = append(devices, device)
	}
	return devices, nil
}

// status lee CPU, memoria, temperatura y uptime del router.
func (z *zteClient) status() *routerStatus {
	z.request("GET", "?_type=menuView&_tag=statusMgr&Menu3Location=0", nil)
	raw, err := z.request("GET", "?_type=menuData&_tag=devmgr_statusmgr_lua.lua", nil)
	if err != nil {
		return nil
	}
	z.raw["status"] = string(raw)
	instances, _ := z.parseInstances(raw)
	all := map[string]string{}
	for _, values := range instances {
		for name, value := range values {
			all[name] = value
		}
	}
	if all["ModelName"] == "" {
		return nil
	}
	status := &routerStatus{Model: all["ModelName"], Firmware: all["SoftwareVer"]}
	cores := 0.0
	for _, key := range []string{"CpuUsage1", "CpuUsage2", "CpuUsage3", "CpuUsage4"} {
		if usage, err := strconv.ParseFloat(all[key], 64); err == nil {
			status.CPU += usage
			cores++
		}
	}
	if cores > 0 {
		status.CPU = round1(status.CPU / cores)
	}
	status.Memory, _ = strconv.ParseFloat(all["MemUsage"], 64)
	status.Temp, _ = strconv.ParseFloat(strings.TrimRight(all["CPUTemp"], "℃°C "), 64)
	status.Uptime, _ = strconv.Atoi(all["PowerOnTime"])
	return status
}

// activeBlocks devuelve las MAC con regla en una red con el filtro activo:
// una regla con el filtro desactivado no bloquea nada. nil = no se pudo leer.
func (z *zteClient) activeBlocks() []string {
	z.request("GET", zteViewAdvanced, nil)
	policies, err := z.instances("acl_policy", zteACLPolicy)
	if err != nil {
		return nil
	}
	rules, err := z.aclRules()
	if err != nil {
		return nil
	}
	policy := map[string]string{}
	for _, values := range policies {
		policy[values["_InstID"]] = values["ACLPolicy"]
	}
	blocked := []string{}
	for _, rule := range rules {
		if policy[rule.Interface] == "Ban" {
			blocked = append(blocked, rule.MAC)
		}
	}
	return blocked
}

// devices inicia sesión, lee los equipos conectados (WiFi y cable) y sale.
func (z *zteClient) devices() ([]routerDevice, error) {
	if err := z.login(); err != nil {
		return nil, err
	}
	defer z.logout()
	var wifiSeen []routerDevice
	defer func() { // antes de cerrar sesión
		z.info = z.status()
		z.moved = z.enforceBlocks(wifiSeen)
		z.blocked = z.activeBlocks()
	}()

	// Página "Estado de la red local": trae señal, red WiFi y puerto LAN.
	// Hay que visitarla antes de pedir sus datos.
	z.request("GET", "?_type=menuView&_tag=localNetStatus&Menu3Location=0", nil)
	detailWifi, errWifi := z.fetch("wlan_clients", "?_type=menuData&_tag=wlan_client_stat_lua.lua", "wifi")
	detailEth, errEth := z.fetch("lan_devices", "?_type=menuData&_tag=accessdev_landevs_lua.lua", "eth")
	wifiSeen = detailWifi
	if errWifi == nil && errEth == nil && len(detailWifi)+len(detailEth) > 0 {
		return append(detailWifi, detailEth...), nil
	}

	// Firmwares sin esa página: lista básica
	const list = "?_type=hiddenData&_tag=accessdev_data&DeveiceType="
	wifi, errWifi := z.fetch("wlan", list+"WLAN", "wifi")
	eth, errEth := z.fetch("eth", list+"ETH", "eth")
	if errWifi == nil && errEth == nil && len(wifi)+len(eth) > 0 {
		return append(wifi, eth...), nil
	}
	// Firmwares que no separan por tipo de conexión
	all, err := z.fetch("all", list+"ALL", "")
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, errors.New("el router no devolvió ningún dispositivo")
	}
	return all, nil
}

func normalizeMAC(mac string) string {
	mac = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"))
	if len(mac) != 17 || strings.Count(mac, ":") != 5 {
		return ""
	}
	return mac
}
