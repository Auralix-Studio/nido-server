package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	fakePassword   = "Clave-De-Prueba"
	fakeLoginToken = "tokenLogin"
	fakePageToken  = "tokenDeLaPaginaDeLogin01"
	fakeSessToken  = "nuevoTokenTrasLogin0001"
)

// zteEncode cifra como lo hace el firmware para los valores marcados "encode".
func zteEncode(value, token string) string {
	runes := []rune(token)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	key := sha256.Sum256([]byte(token))
	iv := sha256.Sum256([]byte(string(runes)))
	data := []byte(value)
	for len(data)%aes.BlockSize != 0 {
		data = append(data, 0)
	}
	block, _ := aes.NewCipher(key[:])
	cipher.NewCBCEncrypter(block, iv[:aes.BlockSize]).CryptBlocks(data, data)
	return base64.StdEncoding.EncodeToString(data)
}

func instance(pairs ...string) string {
	out := "<Instance>"
	for i := 0; i < len(pairs); i += 2 {
		out += fmt.Sprintf("<ParaName>%s</ParaName><ParaValue>%s</ParaValue>", pairs[i], pairs[i+1])
	}
	return out + "</Instance>"
}

// fakeZTE imita el panel de un ZTE F6600P: login con SHA256(clave+token),
// sesión única y lista de equipos en XML.
func fakeZTE(t *testing.T) (*httptest.Server, *bool) {
	loggedIn := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		switch query.Get("_tag") {
		case "":
			if loggedIn {
				fmt.Fprint(w, `<html><a href="/?_type=menuView&_tag=localNetStatus&Menu3Location=0">red</a>
					<script>$.post("/?_type=loginData&_tag=logout_entry");
					var r = "/?_type=menuData&_tag=devmgr_reboot_lua.lua";</script></html>`)
				return
			}
			fmt.Fprint(w, "<html>login</html>")
		case "localNetStatus":
			fmt.Fprint(w, `<div>var addr = "/?_type=hiddenData&amp;_tag=accessdev_data&";</div>`)
		case "devmgr_reboot_lua.lua":
			t.Error("la exploración visitó un endpoint de reinicio")
		case "login_token":
			fmt.Fprintf(w, "<ajax_response_xml_root>%s</ajax_response_xml_root>", fakeLoginToken)
		case "login_entry":
			if r.Method == "GET" {
				fmt.Fprintf(w, `{"lockingTime":0,"loginErrMsg":"","promptMsg":"","sess_token":"%s"}`, fakePageToken)
				return
			}
			r.ParseForm()
			want := sha256.Sum256([]byte(fakePassword + fakeLoginToken))
			if r.Form.Get("Password") != hex.EncodeToString(want[:]) || r.Form.Get("Username") != "admin" ||
				r.Form.Get("_sessionTOKEN") != fakePageToken || r.Form.Get("action") != "login" {
				fmt.Fprint(w, `{"lockingTime":0,"loginErrMsg":"Usuario o clave incorrectos","login_need_refresh":false,"sess_token":"x"}`)
				return
			}
			loggedIn = true
			fmt.Fprintf(w, `{"login_need_refresh":true,"sess_token":"%s"}`, fakeSessToken)
		case "logout_entry":
			r.ParseForm()
			if r.Form.Get("_sessionTOKEN") != fakeSessToken {
				t.Errorf("logout con token incorrecto: %q", r.Form.Get("_sessionTOKEN"))
			}
			loggedIn = false
		case "accessdev_data":
			if !loggedIn {
				fmt.Fprint(w, `<ajax_response_xml_root><IF_ERRORSTR>SessionTimeout</IF_ERRORSTR></ajax_response_xml_root>`)
				return
			}
			body := ""
			switch query.Get("DeveiceType") {
			case "WLAN":
				body = instance("_InstID", "DEV1", "HostName", zteEncode("Movil-Ana", fakeSessToken),
					"IPAddress", "192.168.1.9", "MACAddress", "02:AA:BB:11:22:33") +
					instance("HostName", "", "IPAddress", "0.0.0.0", "MACAddress", "aa:bb:cc:dd:ee:ff")
			case "ETH":
				// con el prefijo que usa el F6600P real
				body = instance("_LuQUID_HostName", zteEncode("servidor", fakeSessToken),
					"_LuQUID_IPAddress", "192.168.1.3", "_LuQUID_MACAddress", "00-11-22-aa-bb-cc")
			}
			fmt.Fprintf(w, `<?xml version="1.0"?><ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR>`+
				`<OBJ_ACCESSDEV_ID>%s</OBJ_ACCESSDEV_ID><encode>HostName</encode></ajax_response_xml_root>`, body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, &loggedIn
}

func TestZTEDevices(t *testing.T) {
	server, loggedIn := fakeZTE(t)
	devices, err := newZTEClient(server.URL, "admin", fakePassword).devices()
	if err != nil {
		t.Fatal(err)
	}
	want := []routerDevice{
		{MAC: "02:aa:bb:11:22:33", IP: "192.168.1.9", Hostname: "Movil-Ana", Conn: "wifi"},
		{MAC: "aa:bb:cc:dd:ee:ff", Conn: "wifi"}, // asociado al WiFi, aún sin IP
		{MAC: "00:11:22:aa:bb:cc", IP: "192.168.1.3", Hostname: "servidor", Conn: "eth"},
	}
	if len(devices) != len(want) {
		t.Fatalf("dispositivos = %+v", devices)
	}
	for i := range want {
		if devices[i] != want[i] {
			t.Errorf("dispositivo %d = %+v, quería %+v", i, devices[i], want[i])
		}
	}
	if *loggedIn {
		t.Error("la sesión del router quedó abierta: debe cerrarse tras leer")
	}
}

func TestZTEExplore(t *testing.T) {
	server, loggedIn := fakeZTE(t)
	dir := t.TempDir()
	results, err := newZTEClient(server.URL, "admin", fakePassword).explore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var visited []string
	for _, r := range results {
		visited = append(visited, r.Query)
	}
	want := []string{"", "?_type=menuView&_tag=localNetStatus&Menu3Location=0", "?_type=hiddenData&_tag=accessdev_data"}
	if fmt.Sprint(visited) != fmt.Sprint(want) {
		t.Errorf("visitados = %q, quería %q", visited, want)
	}
	if *loggedIn {
		t.Error("la sesión del router quedó abierta tras explorar")
	}
}

func TestZTEWrongPassword(t *testing.T) {
	server, _ := fakeZTE(t)
	_, err := newZTEClient(server.URL, "admin", "otra-clave").devices()
	if !errors.Is(err, errRouterAuth) {
		t.Fatalf("error = %v, quería errRouterAuth", err)
	}
}
