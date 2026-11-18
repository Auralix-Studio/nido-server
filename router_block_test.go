package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeACLRouter imita la parte de escritura del F6600P: token por página,
// cabecera Check firmada con la clave pública, reglas y políticas del filtro MAC.
type fakeACLRouter struct {
	t        *testing.T
	key      *rsa.PrivateKey
	token    int
	rules    map[string][2]string // id -> {mac, interfaz}
	nextRule int
	policy   []string // política de AP1..AP4
	posts    []string
}

func hexEscape(text string) string {
	out := ""
	for _, b := range []byte(text) {
		out += fmt.Sprintf(`\x%02x`, b)
	}
	return out
}

func (f *fakeACLRouter) currentToken() string { return fmt.Sprintf("tokenDePagina%04d", f.token) }

func (f *fakeACLRouter) handle(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("_tag")
	const succ = "<IF_ERRORSTR>SUCC</IF_ERRORSTR>"
	if r.Method == "POST" && tag != "login_entry" && tag != "logout_entry" {
		body, _ := io.ReadAll(r.Body)
		check, _ := base64.StdEncoding.DecodeString(r.Header.Get("Check"))
		plain, err := rsa.DecryptPKCS1v15(rand.Reader, f.key, check)
		digest := sha256.Sum256(body)
		form, _ := url.ParseQuery(string(body))
		if err != nil || string(plain) != hex.EncodeToString(digest[:]) || form.Get("_sessionTOKEN") != f.currentToken() {
			fmt.Fprint(w, "<ajax_response_xml_root><IF_ERRORSTR>SessionTimeout</IF_ERRORSTR></ajax_response_xml_root>")
			return
		}
		f.posts = append(f.posts, string(body))
		switch {
		case tag == "wlan_macfilterrule_lua.lua" && form.Get("IF_ACTION") == "Delete":
			delete(f.rules, form.Get("_InstID"))
		case tag == "wlan_macfilterrule_lua.lua":
			for _, rule := range f.rules { // como el F6600P: una regla por MAC
				if rule[0] == form.Get("MACAddress") {
					fmt.Fprint(w, "<ajax_response_xml_root><IF_ERRORID>-258</IF_ERRORID><IF_ERRORSTR>FAIL</IF_ERRORSTR></ajax_response_xml_root>")
					return
				}
			}
			f.nextRule++
			f.rules[fmt.Sprintf("DEV.ACL%d", f.nextRule)] = [2]string{form.Get("MACAddress"), form.Get("Interface")}
		case tag == "wlan_macfilteraclpolicy_lua.lua":
			for i := range f.policy {
				if form.Get(fmt.Sprintf("_InstID_%d", i)) != fmt.Sprintf("DEV.WIFI.AP%d", i+1) {
					f.t.Errorf("formulario de políticas incompleto: %s", body)
				}
				f.policy[i] = form.Get(fmt.Sprintf("ACLPolicy_%d", i))
			}
		}
		fmt.Fprintf(w, "<ajax_response_xml_root>%s</ajax_response_xml_root>", succ)
		return
	}

	switch tag {
	case "":
		der, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
		text := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		fmt.Fprintf(w, `<script>var pubKey = "%s";</script>`, strings.ReplaceAll(strings.TrimSpace(text), "\n", `\n`))
	case "login_token":
		fmt.Fprintf(w, "<ajax_response_xml_root>%s</ajax_response_xml_root>", fakeLoginToken)
	case "login_entry":
		if r.Method == "GET" {
			fmt.Fprintf(w, `{"lockingTime":0,"sess_token":"%s"}`, fakePageToken)
			return
		}
		fmt.Fprintf(w, `{"login_need_refresh":true,"sess_token":"%s"}`, fakeSessToken)
	case "wlanAdvanced", "wlanBasic":
		f.token++ // cada página emite un token nuevo y caduca el anterior
		fmt.Fprintf(w, `<script>_sessionTmpToken = "%s";</script>`, hexEscape(f.currentToken()))
	case "wlan_wlansssidconf_lua.lua":
		fmt.Fprintf(w, "<ajax_response_xml_root>%s<OBJ_WLANAP_ID>%s%s%s</OBJ_WLANAP_ID></ajax_response_xml_root>", succ,
			instance("_InstID", "DEV.WIFI.AP1", "Enable", "1", "ESSID", "CASA 2.4G"),
			instance("_InstID", "DEV.WIFI.AP2", "Enable", "0", "ESSID", "INVITADOS"),
			instance("_InstID", "DEV.WIFI.AP3", "Enable", "1", "ESSID", "CASA 5G"))
	case "wlan_macfilteraclpolicy_lua.lua":
		body := instance("_InstID", "DEV.WIFI.RD1", "Band", "2.4GHz")
		for i, policy := range f.policy {
			body += instance("_InstID", fmt.Sprintf("DEV.WIFI.AP%d", i+1), "ACLPolicy", policy)
		}
		fmt.Fprintf(w, "<ajax_response_xml_root>%s%s</ajax_response_xml_root>", succ, body)
	case "wlan_macfilterrule_lua.lua":
		body := ""
		for id, rule := range f.rules {
			body += instance("_InstID", id, "Name", "x", "MACAddress", rule[0], "Interface", rule[1])
		}
		fmt.Fprintf(w, "<ajax_response_xml_root>%s<OBJ_ACLCFG_ID>%s</OBJ_ACLCFG_ID></ajax_response_xml_root>", succ, body)
	}
}

func newFakeACLRouter(t *testing.T) (*fakeACLRouter, *zteClient) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeACLRouter{t: t, key: key, rules: map[string][2]string{},
		policy: []string{"Disabled", "Disabled", "Disabled", "Disabled"}}
	server := httptest.NewServer(http.HandlerFunc(fake.handle))
	t.Cleanup(server.Close)
	return fake, newZTEClient(server.URL, "admin", fakePassword)
}

func TestZTEBlockAndUnblock(t *testing.T) {
	fake, client := newFakeACLRouter(t)
	const mac = "02:aa:bb:11:22:33"

	// Conectado a la red 5G (AP3): una sola regla, en esa red
	if err := client.setBlocked(mac, true, "CASA 5G"); err != nil {
		t.Fatal(err)
	}
	if len(fake.rules) != 1 {
		t.Fatalf("reglas = %v", fake.rules)
	}
	for _, rule := range fake.rules {
		if rule != [2]string{mac, "DEV.WIFI.AP3"} {
			t.Errorf("regla = %v", rule)
		}
	}
	// Todas las redes activas en lista negra; la desactivada (AP2) intacta
	if got := strings.Join(fake.policy, ","); got != "Ban,Disabled,Ban,Disabled" {
		t.Errorf("políticas = %s", got)
	}

	// Repetir el bloqueo no envía cambios
	posts := len(fake.posts)
	if err := client.setBlocked(mac, true, "CASA 5G"); err != nil {
		t.Fatal(err)
	}
	if len(fake.posts) != posts {
		t.Errorf("el segundo bloqueo envió cambios: %v", fake.posts[posts:])
	}

	// Sin red conocida: la primera red activa
	other := "02:aa:bb:44:55:66"
	if err := client.setBlocked(other, true, ""); err != nil {
		t.Fatal(err)
	}

	if err := client.setBlocked(mac, false, ""); err != nil {
		t.Fatal(err)
	}
	for _, rule := range fake.rules {
		if rule[0] == mac {
			t.Errorf("quedó la regla tras desbloquear: %v", rule)
		}
	}
}

func TestZTEEnforceFollowsBand(t *testing.T) {
	fake, client := newFakeACLRouter(t)
	const mac = "02:aa:bb:11:22:33"
	if err := client.setBlocked(mac, true, "CASA 2.4G"); err != nil {
		t.Fatal(err)
	}
	// El equipo aparece ahora en la red 5G: la regla debe moverse allí
	if err := client.login(); err != nil {
		t.Fatal(err)
	}
	moved := client.enforceBlocks([]routerDevice{{MAC: mac, Conn: "wifi", SSID: "CASA 5G"}})
	if len(moved) != 1 || len(fake.rules) != 1 {
		t.Fatalf("movidos = %v, reglas = %v", moved, fake.rules)
	}
	for _, rule := range fake.rules {
		if rule[1] != "DEV.WIFI.AP3" {
			t.Errorf("la regla sigue en %s", rule[1])
		}
	}
	if blocked := client.activeBlocks(); len(blocked) != 1 || blocked[0] != mac {
		t.Errorf("bloqueados activos = %v", blocked)
	}
}

func TestZTEBlockedNeedsPolicy(t *testing.T) {
	fake, client := newFakeACLRouter(t)
	// Regla sin filtro activo (lo que pasaba antes): no cuenta como bloqueado
	fake.rules["DEV.ACL9"] = [2]string{"02:aa:bb:11:22:33", "DEV.WIFI.AP1"}
	if err := client.login(); err != nil {
		t.Fatal(err)
	}
	if blocked := client.activeBlocks(); len(blocked) != 0 {
		t.Errorf("una regla con el filtro desactivado no bloquea: %v", blocked)
	}
}

func TestZTEBlockRespectsWhitelist(t *testing.T) {
	fake, client := newFakeACLRouter(t)
	fake.policy[0] = "Allow" // el dueño usa lista blanca en la red principal
	if err := client.setBlocked("02:aa:bb:11:22:33", true, ""); err == nil {
		t.Fatal("debería negarse a tocar un filtro en modo lista blanca")
	}
	if len(fake.posts) != 0 {
		t.Errorf("se enviaron cambios pese a la lista blanca: %v", fake.posts)
	}
}
