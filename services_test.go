package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fakeShow = `Id=nginx.service
Description=A high performance web server
ActiveState=active
SubState=running
MainPID=812
ControlGroup=/system.slice/nginx.service
MemoryCurrent=12890112
CPUUsageNSec=482000000
ActiveEnterTimestampMonotonic=1000000
NRestarts=0
UnitFileState=enabled

Id=sshd.service
Description=OpenSSH Daemon
ActiveState=inactive
SubState=dead
MainPID=0
ControlGroup=
MemoryCurrent=[not set]
CPUUsageNSec=18446744073709551615
ActiveEnterTimestampMonotonic=0
NRestarts=2
UnitFileState=disabled
`

// fakeSystem sustituye systemctl/journalctl por respuestas fijas.
func fakeSystem(t *testing.T) (*ServiceManager, *[]string) {
	var calls []string
	oldRun, oldHas := run, hasCommand
	t.Cleanup(func() { run, hasCommand = oldRun, oldHas })
	hasCommand = func(name string) bool { return name == "systemctl" }
	run = func(_ time.Duration, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch {
		case name == "systemctl" && args[0] == "list-units":
			return "nginx.service loaded active running A high performance web server\n", nil
		case name == "systemctl" && args[0] == "show":
			return fakeShow, nil
		case name == "journalctl":
			return "2026-11-16T10:00:00 host nginx[812]: started\n", nil
		}
		return "", nil
	}
	cfg.Services.ShowAllRunning, cfg.Services.AllowActions = true, true
	store := openStore(filepath.Join(t.TempDir(), "state.json"))
	store.setWatched("sshd.service", true)
	return newServiceManager(store), &calls
}

func TestSystemdServices(t *testing.T) {
	manager, calls := fakeSystem(t)
	services := manager.list()
	if len(services) != 2 {
		t.Fatalf("servicios = %+v", services)
	}
	sshd, nginx := services[0], services[1] // los fijados van primero
	if sshd.Unit != "sshd.service" || !sshd.Watched || sshd.Running || sshd.MemoryBytes != nil || sshd.Restarts != 2 {
		t.Errorf("sshd = %+v", sshd)
	}
	if nginx.ID != "systemd:nginx.service" || !nginx.Running || !nginx.Enabled || nginx.Watched ||
		nginx.PID == nil || *nginx.PID != 812 || nginx.MemoryBytes == nil || *nginx.MemoryBytes != 12890112 {
		t.Errorf("nginx = %+v", nginx)
	}

	if err := manager.action("systemd:nginx.service", "restart"); err != nil {
		t.Fatal(err)
	}
	if last := (*calls)[len(*calls)-1]; last != "systemctl restart nginx.service" {
		t.Errorf("comando = %q", last)
	}
	if logs, err := manager.logs("systemd:nginx.service", 50); err != nil || len(logs) != 1 {
		t.Errorf("logs = %v, %v", logs, err)
	}
	if err := manager.setWatched("systemd:nginx.service", true); err != nil {
		t.Fatal(err)
	}
	if !manager.list()[0].Watched || !manager.list()[1].Watched {
		t.Error("nginx debería quedar fijado")
	}
}

func TestServiceActionRejectsUnknown(t *testing.T) {
	manager, calls := fakeSystem(t)
	manager.list()
	before := len(*calls)
	for _, id := range []string{"systemd:evil.service; rm -rf /", "docker:nope", "x", "systemd:"} {
		if err := manager.action(id, "stop"); err == nil {
			t.Errorf("%q debería rechazarse", id)
		}
	}
	if err := manager.action("systemd:nginx.service", "destroy"); err == nil {
		t.Error("acción inválida aceptada")
	}
	for _, call := range (*calls)[before:] {
		if strings.Contains(call, "stop") || strings.Contains(call, "destroy") {
			t.Errorf("se ejecutó un comando para un servicio no válido: %q", call)
		}
	}
}

func TestTokenRoundTrip(t *testing.T) {
	secrets.JWTSecret = "clave-de-prueba"
	cfg.Auth.JWTExpiryHours = 1
	token := createToken("192.168.1.50")
	if !verifyToken(token) {
		t.Fatal("token válido rechazado")
	}
	if verifyToken(token[:len(token)-2]+"xx") || verifyToken("a.b.c") || verifyToken("") {
		t.Error("token manipulado aceptado")
	}
	cfg.Auth.JWTExpiryHours = -1
	if verifyToken(createToken("x")) {
		t.Error("token caducado aceptado")
	}
}
