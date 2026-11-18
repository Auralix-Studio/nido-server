package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Bloqueo de dispositivos con el filtro MAC WiFi del router ("WLAN Avanzado").
//
// Bloquear = añadir una regla con la MAC en cada red WiFi activa y poner esas
// redes en modo lista negra ("Ban"). Los demás equipos no se ven afectados.
// Solo sirve para WiFi: este firmware no ofrece filtro MAC para los puertos LAN.

var (
	rePageToken = regexp.MustCompile(`_sessionTmpToken = "((?:\\x[0-9a-fA-F]{2})+)"`)
	rePubKey    = regexp.MustCompile(`-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----`)
)

const (
	zteViewAdvanced = "?_type=menuView&_tag=wlanAdvanced&Menu3Location=0"
	zteACLPolicy    = "?_type=menuData&_tag=wlan_macfilteraclpolicy_lua.lua"
	zteACLRules     = "?_type=menuData&_tag=wlan_macfilterrule_lua.lua"
	zteViewBasic    = "?_type=menuView&_tag=wlanBasic&Menu3Location=0"
	zteSSIDConf     = "?_type=menuData&_tag=wlan_wlansssidconf_lua.lua"
)

type aclRule struct {
	ID, Name, Interface, MAC string
}

// escape codifica como encodeURIComponent del navegador.
func escape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

// refreshPageKeys prepara lo que el router exige para aceptar un cambio: la
// clave pública (página principal, una sola vez) y un token de formulario
// fresco, que viene en la página del menú y caduca al abrir otra.
func (z *zteClient) refreshPageKeys() error {
	if z.pubKey == nil {
		page, err := z.request("GET", "", nil)
		if err != nil {
			return err
		}
		keyText := strings.ReplaceAll(string(rePubKey.Find(page)), `\n`, "\n")
		block, _ := pem.Decode([]byte(keyText))
		if block == nil {
			return errors.New("no se encontró la clave pública del router")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return errors.New("la clave pública del router no es RSA")
		}
		z.pubKey = key
	}
	view, err := z.request("GET", zteViewAdvanced, nil)
	if err != nil {
		return err
	}
	tokens := rePageToken.FindAllSubmatch(view, -1)
	if len(tokens) == 0 {
		return errors.New("no se encontró el token de formulario del router")
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(string(tokens[len(tokens)-1][1]), `\x`, ""))
	if err != nil {
		return err
	}
	z.token = string(raw)
	return nil
}

// post envía un cambio de configuración firmado y devuelve el error del router, si lo hay.
func (z *zteClient) post(query, data string) error {
	if err := z.refreshPageKeys(); err != nil {
		return err
	}
	// Como el navegador: cargar los datos del formulario antes de guardarlo
	z.request("GET", query, nil)
	data += "&_sessionTOKEN=" + z.token
	digest := sha256.Sum256([]byte(data))
	check, err := rsa.EncryptPKCS1v15(rand.Reader, z.pubKey, []byte(hex.EncodeToString(digest[:])))
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", z.base+"/"+query, strings.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Referer", z.base+"/")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Check", base64.StdEncoding.EncodeToString(check))
	resp, err := z.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	z.raw["post "+query] = string(body)
	_, errStr := z.parseInstances(body)
	if errStr != "SUCC" {
		if errStr == "" {
			errStr = fmt.Sprintf("respuesta inesperada (HTTP %d)", resp.StatusCode)
		}
		return fmt.Errorf("el router rechazó el cambio: %s", errStr)
	}
	return nil
}

func (z *zteClient) instances(label, query string) ([]map[string]string, error) {
	raw, err := z.request("GET", query, nil)
	if err != nil {
		return nil, err
	}
	z.raw[label] = string(raw)
	instances, errStr := z.parseInstances(raw)
	if errStr != "" && errStr != "SUCC" {
		return nil, fmt.Errorf("el router devolvió %s", errStr)
	}
	return instances, nil
}

// activeSSIDs devuelve los puntos de acceso habilitados (p. ej. DEV.WIFI.AP1 y AP5).
func (z *zteClient) activeSSIDs() ([]string, error) {
	z.request("GET", zteViewBasic, nil)
	instances, err := z.instances("ssids", zteSSIDConf)
	if err != nil {
		return nil, err
	}
	var active []string
	for _, values := range instances {
		if strings.Contains(values["_InstID"], ".AP") && values["ESSID"] != "" && values["Enable"] == "1" {
			active = append(active, values["_InstID"])
		}
	}
	if len(active) == 0 {
		return nil, errors.New("el router no tiene redes WiFi activas")
	}
	return active, nil
}

func (z *zteClient) aclRules() ([]aclRule, error) {
	instances, err := z.instances("acl_rules", zteACLRules)
	if err != nil {
		return nil, err
	}
	var rules []aclRule
	for _, values := range instances {
		if mac := normalizeMAC(values["MACAddress"]); mac != "" {
			rules = append(rules, aclRule{ID: values["_InstID"], Name: values["Name"],
				Interface: values["Interface"], MAC: mac})
		}
	}
	return rules, nil
}

// blockedMACs inicia sesión y devuelve las MAC con regla de bloqueo.
func (z *zteClient) blockedMACs() ([]string, error) {
	if err := z.login(); err != nil {
		return nil, err
	}
	defer z.logout()
	z.request("GET", zteViewAdvanced, nil)
	rules, err := z.aclRules()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var macs []string
	for _, rule := range rules {
		if !seen[rule.MAC] {
			seen[rule.MAC] = true
			macs = append(macs, rule.MAC)
		}
	}
	return macs, nil
}

// writeSelfTest comprueba que el router acepta cambios firmados sin afectar a
// nadie: crea y borra una regla para una MAC inexistente y reenvía la política
// actual de una red sin cambiarla.
func (z *zteClient) writeSelfTest() error {
	const fakeMAC = "02:00:00:a0:a0:01"
	if err := z.login(); err != nil {
		return err
	}
	defer z.logout()
	ssids, err := z.activeSSIDs()
	if err != nil {
		return err
	}
	z.request("GET", zteViewAdvanced, nil)
	policies, err := z.instances("acl_policy", zteACLPolicy)
	if err != nil {
		return err
	}
	current := ""
	for _, values := range policies {
		if values["_InstID"] == ssids[0] {
			current = values["ACLPolicy"]
		}
	}
	fmt.Printf("Redes activas: %v, política de %s: %s\n", ssids, ssids[0], current)

	data := "IF_ACTION=Apply&_InstID=-1&MACAddress=" + escape(fakeMAC) + "&Name=nido_selftest&Interface=" + escape(ssids[0])
	if err := z.post(zteACLRules, data); err != nil {
		return fmt.Errorf("crear regla: %w", err)
	}
	z.request("GET", zteViewAdvanced, nil)
	rules, err := z.aclRules()
	if err != nil {
		return err
	}
	fmt.Printf("Tras crear: %+v\n", rules)
	deleted := false
	for _, rule := range rules {
		if rule.MAC == fakeMAC {
			if err := z.post(zteACLRules, "IF_ACTION=Delete&_InstID="+escape(rule.ID)); err != nil {
				return fmt.Errorf("borrar regla: %w", err)
			}
			deleted = true
		}
	}
	if !deleted {
		return errors.New("la regla de prueba no apareció en la lista")
	}
	z.request("GET", zteViewAdvanced, nil)
	rules, _ = z.aclRules()
	fmt.Printf("Tras borrar: %+v\n", rules)

	if current != "" {
		if err := z.savePolicies(policies, nil); err != nil {
			return fmt.Errorf("reenviar política: %w", err)
		}
		fmt.Println("Política reenviada sin cambios: aceptada")
	}
	return nil
}

// savePolicies guarda el formulario de políticas. El panel envía todas las
// redes a la vez con índices (_InstID_0, ACLPolicy_0, ...): se reenvían los
// valores actuales cambiando solo las redes indicadas.
func (z *zteClient) savePolicies(policies []map[string]string, change map[string]string) error {
	var fields []string
	index := 0
	for _, values := range policies {
		current, isAP := values["ACLPolicy"]
		if !isAP {
			continue // las entradas de radio (RD1, RD2) no llevan política
		}
		if wanted, ok := change[values["_InstID"]]; ok {
			current = wanted
		}
		fields = append(fields,
			fmt.Sprintf("_InstID_%d=%s", index, escape(values["_InstID"])),
			fmt.Sprintf("ACLPolicy_%d=%s", index, escape(current)))
		index++
	}
	if index == 0 {
		return errors.New("el router no devolvió las políticas del filtro MAC")
	}
	data := fmt.Sprintf("IF_ACTION=Apply&_InstNum=%d&%s", index, strings.Join(fields, "&"))
	return z.post(zteACLPolicy, data)
}

// El router admite una sola regla por MAC y cada regla actúa solo en la red
// (banda) que indica. Por eso la regla se pone en la red donde está el equipo
// y, si aparece conectado en otra, enforceBlocks la mueve allí.

// ssidAPs devuelve nombre de red -> punto de acceso de las redes activas.
func (z *zteClient) ssidAPs() (map[string]string, error) {
	z.request("GET", zteViewBasic, nil)
	instances, err := z.instances("ssids", zteSSIDConf)
	if err != nil {
		return nil, err
	}
	aps := map[string]string{}
	for _, values := range instances {
		if strings.Contains(values["_InstID"], ".AP") && values["ESSID"] != "" && values["Enable"] == "1" {
			aps[values["ESSID"]] = values["_InstID"]
		}
	}
	if len(aps) == 0 {
		return nil, errors.New("el router no tiene redes WiFi activas")
	}
	return aps, nil
}

// placeRule deja una única regla para la MAC, en el punto de acceso indicado.
func (z *zteClient) placeRule(mac, ap string, rules []aclRule) error {
	for _, rule := range rules {
		if rule.MAC != mac {
			continue
		}
		if rule.Interface == ap {
			return nil
		}
		if err := z.post(zteACLRules, "IF_ACTION=Delete&_InstID="+escape(rule.ID)); err != nil {
			return fmt.Errorf("mover regla: %w", err)
		}
	}
	name := "nido_" + strings.ReplaceAll(mac, ":", "")[6:]
	data := "IF_ACTION=Apply&_InstID=-1&MACAddress=" + escape(mac) + "&Name=" + escape(name) + "&Interface=" + escape(ap)
	if err := z.post(zteACLRules, data); err != nil {
		return fmt.Errorf("crear regla: %w", err)
	}
	return nil
}

// ensureBan pone en lista negra todas las redes activas. Sin reglas para
// otros equipos, la lista negra no afecta a nadie más.
func (z *zteClient) ensureBan(aps map[string]string) error {
	z.request("GET", zteViewAdvanced, nil)
	policies, err := z.instances("acl_policy", zteACLPolicy)
	if err != nil {
		return err
	}
	change := map[string]string{}
	for _, values := range policies {
		for _, ap := range aps {
			if values["_InstID"] != ap {
				continue
			}
			switch values["ACLPolicy"] {
			case "Allow":
				return errors.New("el router usa el filtro MAC en modo lista blanca; no lo modifico")
			case "Ban":
			default:
				change[ap] = "Ban"
			}
		}
	}
	if len(change) == 0 {
		return nil
	}
	if err := z.savePolicies(policies, change); err != nil {
		return fmt.Errorf("activar filtro: %w", err)
	}
	return nil
}

// isSessionError indica que el router cortó la sesión a mitad de operación.
func isSessionError(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "SessionTimeout") || strings.Contains(text, "caducado")
}

// withSession inicia sesión, ejecuta la operación y, si el router corta la
// sesión a mitad (otro login, caducidad), vuelve a entrar y la repite una vez.
func (z *zteClient) withSession(op func() error) error {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if err = z.login(); err != nil {
			return err
		}
		err = op()
		z.logout()
		if !isSessionError(err) {
			return err
		}
		log.Printf("Router: sesión cortada (%v), reintentando", err)
		z.pubKey = nil
	}
	return err
}

// setBlocked bloquea o desbloquea una MAC. connectedSSID es la red en la que
// está ahora el equipo ("" si no se sabe).
func (z *zteClient) setBlocked(mac string, block bool, connectedSSID string) error {
	mac = normalizeMAC(mac)
	if mac == "" {
		return errors.New("MAC inválida")
	}
	return z.withSession(func() error {
		var aps map[string]string
		if block {
			var err error
			if aps, err = z.ssidAPs(); err != nil {
				return err
			}
		}
		z.request("GET", zteViewAdvanced, nil)
		rules, err := z.aclRules()
		if err != nil {
			return err
		}
		if !block {
			for _, rule := range rules {
				if rule.MAC == mac {
					if err := z.post(zteACLRules, "IF_ACTION=Delete&_InstID="+escape(rule.ID)); err != nil {
						return err
					}
				}
			}
			return nil
		}

		// No tocar nada si el dueño usa el filtro como lista blanca
		policies, err := z.instances("acl_policy", zteACLPolicy)
		if err != nil {
			return err
		}
		for _, values := range policies {
			for _, active := range aps {
				if values["_InstID"] == active && values["ACLPolicy"] == "Allow" {
					return errors.New("el router usa el filtro MAC en modo lista blanca; no lo modifico")
				}
			}
		}

		ap := aps[connectedSSID]
		if ap == "" {
			ap = firstAP(aps)
		}
		if err := z.placeRule(mac, ap, rules); err != nil {
			return err
		}
		if err := z.ensureBan(aps); err != nil {
			// Sin filtro activo la regla no hace nada: deshacerla para no
			// dejar un "bloqueado" que en realidad no bloquea.
			z.request("GET", zteViewAdvanced, nil)
			if current, readErr := z.aclRules(); readErr == nil {
				for _, rule := range current {
					if rule.MAC == mac {
						z.post(zteACLRules, "IF_ACTION=Delete&_InstID="+escape(rule.ID))
					}
				}
			}
			return err
		}
		return nil
	})
}

func firstAP(aps map[string]string) string {
	best := ""
	for _, ap := range aps {
		if best == "" || ap < best {
			best = ap
		}
	}
	return best
}

// enforceBlocks mueve la regla de un equipo bloqueado que se ha conectado por
// otra banda. Se llama con la sesión ya iniciada. Devuelve los equipos movidos.
func (z *zteClient) enforceBlocks(connected []routerDevice) []string {
	aps, err := z.ssidAPs()
	if err != nil {
		return nil
	}
	z.request("GET", zteViewAdvanced, nil)
	rules, err := z.aclRules()
	if err != nil {
		return nil
	}
	ruleAP := map[string]string{}
	for _, rule := range rules {
		ruleAP[rule.MAC] = rule.Interface
	}
	var moved []string
	for _, d := range connected {
		current, blocked := ruleAP[d.MAC]
		ap := aps[d.SSID]
		if !blocked || d.Conn != "wifi" || ap == "" || ap == current {
			continue
		}
		if err := z.placeRule(d.MAC, ap, rules); err != nil {
			log.Printf("Router: no se pudo mover el bloqueo de %s: %v", d.MAC, err)
			continue
		}
		moved = append(moved, d.MAC)
	}
	if len(moved) > 0 {
		if err := z.ensureBan(aps); err != nil {
			log.Printf("Router: %v", err)
		}
	}
	return moved
}
