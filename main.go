// Nido — servidor para administrar el servidor de casa y la red local.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

// ---------- alertas ----------

func (a *App) notify(typ, message, mac string, push bool) {
	log.Printf("EVENTO %s: %s", typ, message)
	a.store.addEvent(typ, message, mac)
	enabled := map[string]bool{"new_device": cfg.Alerts.NewDevice, "service_down": cfg.Alerts.ServiceDown}
	if on, listed := enabled[typ]; !push || cfg.Alerts.NtfyURL == "" || (listed && !on) {
		return
	}
	go func() {
		req, err := http.NewRequest("POST", cfg.Alerts.NtfyURL, bytes.NewBufferString(message))
		if err != nil {
			return
		}
		req.Header.Set("Title", "Nido")
		client := http.Client{Timeout: 10 * time.Second}
		if resp, err := client.Do(req); err != nil {
			log.Printf("No se pudo enviar el aviso a ntfy: %v", err)
		} else {
			resp.Body.Close()
		}
	}()
}

// ---------- tareas en segundo plano ----------

func (a *App) watchServices(previous map[string]bool) map[string]bool {
	current := map[string]bool{}
	for _, s := range a.services.list() {
		if !s.Watched {
			continue
		}
		current[s.ID] = s.Running
		was, known := previous[s.ID]
		_, name, _ := strings.Cut(s.ID, ":")
		if known && was && !s.Running {
			a.notify("service_down", "Servicio caído: "+name, "", true)
		} else if known && !was && s.Running {
			a.notify("service_up", "Servicio recuperado: "+name, "", false)
		}
	}
	return current
}

func (a *App) backgroundLoop() {
	go func() {
		states := map[string]bool{}
		for {
			states = a.watchServices(states)
			time.Sleep(time.Duration(cfg.Services.CheckIntervalSeconds) * time.Second)
		}
	}()
	interval := time.Duration(cfg.Network.ScanIntervalSeconds) * time.Second
	for {
		a.scanner.scan()
		select {
		case <-a.scanNow:
		case <-time.After(interval):
		}
	}
}

func discoveryLoop(port int) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: cfg.Server.DiscoveryPort})
	if err != nil {
		log.Printf("Descubrimiento desactivado: %v", err)
		return
	}
	buf := make([]byte, 64)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err == nil {
			switch string(buf[:n]) {
			case "NIDO_DISCOVER":
				conn.WriteToUDP([]byte(fmt.Sprintf("NIDO_HERE:%s:%d", localIP(), port)), addr)
			case "AURAHOME_DISCOVER":
				conn.WriteToUDP([]byte(fmt.Sprintf("AURAHOME_HERE:%s:%d", localIP(), port)), addr)
			}
		}
	}
}

// ---------- certificado ----------

func ensureCertificate(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}
	log.Print("Generando certificado auto-firmado...")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nido"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if ip := net.ParseIP(localIP()); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

// ---------- comandos ----------

func prompt(label string) string {
	fmt.Print(label)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatalf("No se pudo leer la entrada: %v", err)
	}
	return strings.TrimSpace(string(value))
}

func setPin() {
	pin := flag.Arg(0)
	if pin == "" {
		pin = prompt("Nuevo PIN (4 dígitos): ")
	}
	if len(pin) != 4 || strings.Trim(pin, "0123456789") != "" {
		log.Fatal("El PIN debe tener exactamente 4 dígitos")
	}
	hash, err := hashPin(pin)
	if err != nil {
		log.Fatal(err)
	}
	secrets.PinHash = hash
	if err := saveSecrets(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("PIN guardado. Reinicia el servicio para aplicarlo.")
}

func setRouterPassword() {
	// Admite la contraseña como argumento para terminales sin entrada interactiva
	if flag.NArg() > 0 {
		secrets.RouterPassword = flag.Arg(0)
	} else {
		secrets.RouterPassword = prompt("Contraseña del panel web del router: ")
	}
	if secrets.RouterPassword == "" {
		log.Fatal("Contraseña vacía")
	}
	if err := saveSecrets(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Contraseña guardada en %s. Pruébala con --router-test.\n", secretsPath())
}

func routerClient() (*zteClient, error) {
	if secrets.RouterPassword == "" {
		return nil, errors.New("primero guarda la contraseña con --set-router-password")
	}
	info, err := detectNetwork()
	if err != nil {
		return nil, err
	}
	return newZTEClient(routerURL(info), cfg.Router.Username, secrets.RouterPassword), nil
}

// routerTest hace un único login y muestra lo que devuelve el router.
func routerTest(raw bool) {
	client, err := routerClient()
	if err != nil {
		log.Fatal(err)
	}
	devices, err := client.devices()
	if raw {
		for label, body := range client.raw {
			fmt.Printf("----- %s -----\n%s\n", label, body)
		}
	}
	if err != nil {
		log.Fatalf("Fallo: %v", err)
	}
	fmt.Printf("Login correcto en %s como %q: %d dispositivos\n", client.base, cfg.Router.Username, len(devices))
	for _, d := range devices {
		detail := d.Port
		if d.Conn == "wifi" {
			detail = fmt.Sprintf("%d dBm  %s", d.Signal, d.SSID)
		}
		fmt.Printf("  %-15s %s  %-5s %-18s %s\n", d.IP, d.MAC, d.Conn, d.Hostname, detail)
	}
	if client.info != nil {
		fmt.Printf("Router: %+v\n", *client.info)
	}
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	host := flag.String("host", "", "Host a escuchar")
	port := flag.Int("port", 0, "Puerto a escuchar")
	doSetPin := flag.Bool("set-pin", false, "Guarda el PIN de acceso de la app y termina")
	doSetRouter := flag.Bool("set-router-password", false, "Guarda la contraseña del router y termina")
	doRouterTest := flag.Bool("router-test", false, "Prueba el login en el router y lista los dispositivos")
	doRouterExplore := flag.Bool("router-explore", false, "Recorre el panel del router y guarda todos sus endpoints de lectura")
	doWriteTest := flag.Bool("router-write-test", false, "Comprueba que el router acepta cambios (crea y borra una regla de prueba)")
	rawDump := flag.Bool("raw", false, "Con --router-test: muestra las respuestas crudas del router")
	flag.Parse()

	loadConfig()
	switch {
	case *doSetPin:
		setPin()
		return
	case *doSetRouter:
		setRouterPassword()
		return
	case *doRouterTest:
		routerTest(*rawDump)
		return
	case *doWriteTest:
		client, err := routerClient()
		if err == nil {
			err = client.writeSelfTest()
		}
		if *rawDump && client != nil {
			for label, body := range client.raw {
				fmt.Printf("----- %s -----\n%.600s\n", label, body)
			}
		}
		if err != nil {
			log.Fatalf("Fallo: %v", err)
		}
		fmt.Println("El router acepta cambios firmados.")
		return
	case *doRouterExplore:
		if err := routerExplore(); err != nil {
			log.Fatalf("Fallo: %v", err)
		}
		return
	}

	ensureJWTSecret()
	if secrets.PinHash == "" {
		log.Print("AVISO: no hay PIN configurado, ejecuta 'nido --set-pin'")
	}
	if *host != "" {
		cfg.Server.Host = *host
	}
	if *port != 0 {
		cfg.Server.Port = *port
	}

	store := openStore(resolvePath(cfg.Storage.Path))
	app := &App{store: store, services: newServiceManager(store), scanNow: make(chan struct{}, 1)}
	app.scanner = &NetworkScanner{store: store, notify: app.notify}

	cert, key := resolvePath(cfg.Server.Cert), resolvePath(cfg.Server.Key)
	if err := ensureCertificate(cert, key); err != nil {
		log.Fatalf("No se pudo crear el certificado: %v", err)
	}

	go app.backgroundLoop()
	go discoveryLoop(cfg.Server.Port)

	addr := net.JoinHostPort(cfg.Server.Host, fmt.Sprint(cfg.Server.Port))
	server := &http.Server{
		Addr:              addr,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(os.Stderr, "", 0),
	}
	source := "escaneo ARP"
	if app.scanner.routerEnabled() {
		source = "router " + cfg.Router.Type
	}
	log.Printf("Nido en https://%s (red: %s)", addr, source)
	log.Fatal(server.ListenAndServeTLS(cert, key))
}
