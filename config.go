package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// WatchItem acepta "nginx.service" o {unit: nginx.service, name: "Web"}.
type WatchItem struct {
	Unit string `yaml:"unit"`
	Name string `yaml:"name"`
}

func (w *WatchItem) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		w.Unit = node.Value
		return nil
	}
	type plain WatchItem
	return node.Decode((*plain)(w))
}

type Config struct {
	Server struct {
		Host          string `yaml:"host"`
		Port          int    `yaml:"port"`
		Cert          string `yaml:"cert"`
		Key           string `yaml:"key"`
		DiscoveryPort int    `yaml:"discovery_port"`
		AllowPower    bool   `yaml:"allow_power"`
	} `yaml:"server"`
	Auth struct {
		JWTExpiryHours int `yaml:"jwt_expiry_hours"`
		MaxAttempts    int `yaml:"max_attempts"`
		LockoutMinutes int `yaml:"lockout_minutes"`
	} `yaml:"auth"`
	Services struct {
		Watch                []WatchItem `yaml:"watch"`
		ShowAllRunning       bool        `yaml:"show_all_running"`
		Docker               bool        `yaml:"docker"`
		AllowActions         bool        `yaml:"allow_actions"`
		CheckIntervalSeconds int         `yaml:"check_interval_seconds"`
	} `yaml:"services"`
	Network struct {
		Interface           string `yaml:"interface"`
		Subnet              string `yaml:"subnet"`
		ScanIntervalSeconds int    `yaml:"scan_interval_seconds"`
		OfflineAfterSeconds int    `yaml:"offline_after_seconds"`
	} `yaml:"network"`
	Router struct {
		// "zte" = leer los conectados del panel web del router. "" = desactivado.
		Type     string `yaml:"type"`
		URL      string `yaml:"url"`
		Username string `yaml:"username"`
	} `yaml:"router"`
	TV struct {
		// Vacío = detectar la TV LG en la red por su nombre
		Host string `yaml:"host"`
		MAC  string `yaml:"mac"`
	} `yaml:"tv"`
	Alerts struct {
		NtfyURL     string `yaml:"ntfy_url"`
		NewDevice   bool   `yaml:"new_device"`
		ServiceDown bool   `yaml:"service_down"`
	} `yaml:"alerts"`
	Storage struct {
		Path string `yaml:"path"`
	} `yaml:"storage"`
}

type Secrets struct {
	PinHash        string `yaml:"pin_hash,omitempty"`
	JWTSecret      string `yaml:"jwt_secret,omitempty"`
	RouterPassword string `yaml:"router_password,omitempty"`
	TVClientKey    string `yaml:"tv_client_key,omitempty"`
}

var (
	cfg        Config
	secrets    Secrets
	configPath string
)

func resolveConfigPath() string {
	for _, key := range []string{"NIDO_CONFIG", "AURA_HOME_CONFIG"} {
		if env := os.Getenv(key); env != "" {
			return env
		}
	}
	for _, etc := range []string{"/etc/nido/config.yaml", "/etc/aura-home/config.yaml", "config.yaml"} {
		if _, err := os.Stat(etc); err == nil {
			return etc
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(filepath.Dir(exe), "config.yaml")
}

// resolvePath interpreta las rutas relativas respecto a la carpeta del config.
func resolvePath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(filepath.Dir(configPath), p)
}

func secretsPath() string { return resolvePath("secrets.yaml") }

func loadConfig() {
	configPath = resolveConfigPath()

	cfg.Server.Host = "0.0.0.0"
	cfg.Server.Port = 8443
	cfg.Server.Cert = "certs/cert.pem"
	cfg.Server.Key = "certs/key.pem"
	cfg.Server.DiscoveryPort = 8444
	cfg.Server.AllowPower = true
	cfg.Auth.JWTExpiryHours = 168
	cfg.Auth.MaxAttempts = 5
	cfg.Auth.LockoutMinutes = 5
	cfg.Services.ShowAllRunning = true
	cfg.Services.Docker = true
	cfg.Services.AllowActions = true
	cfg.Services.CheckIntervalSeconds = 30
	cfg.Network.ScanIntervalSeconds = 60
	cfg.Network.OfflineAfterSeconds = 300
	cfg.Router.Type = "zte"
	cfg.Router.Username = "admin"
	cfg.Alerts.NewDevice = true
	cfg.Alerts.ServiceDown = true
	cfg.Storage.Path = "data/state.json"

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Sin %s, usando valores por defecto", configPath)
	} else if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("config.yaml inválido: %v", err)
	}
	if data, err := os.ReadFile(secretsPath()); err == nil {
		if err := yaml.Unmarshal(data, &secrets); err != nil {
			log.Fatalf("secrets.yaml inválido: %v", err)
		}
	}
}

func saveSecrets() error {
	data, err := yaml.Marshal(&secrets)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(secretsPath()), 0o755); err != nil {
		return err
	}
	return os.WriteFile(secretsPath(), data, 0o600)
}

// ensureJWTSecret genera la clave JWT la primera vez que arranca el servidor.
func ensureJWTSecret() {
	if secrets.JWTSecret != "" {
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Fatal(err)
	}
	secrets.JWTSecret = hex.EncodeToString(buf)
	if err := saveSecrets(); err != nil {
		log.Fatalf("No se pudo guardar secrets.yaml: %v", err)
	}
}
