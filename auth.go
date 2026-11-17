package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ---------- PIN ----------

func hashPin(pin string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pin), bcrypt.DefaultCost)
	return string(hash), err
}

func verifyPin(pin string) bool {
	if secrets.PinHash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(secrets.PinHash), []byte(pin)) == nil
}

// ---------- JWT (HS256) ----------

var b64 = base64.RawURLEncoding

const jwtHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"HS256","typ":"JWT"}

type claims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
}

func sign(data string) string {
	mac := hmac.New(sha256.New, []byte(secrets.JWTSecret))
	mac.Write([]byte(data))
	return b64.EncodeToString(mac.Sum(nil))
}

func createToken(subject string) string {
	now := time.Now()
	payload, _ := json.Marshal(claims{
		Sub: subject,
		Iat: now.Unix(),
		Exp: now.Add(time.Duration(cfg.Auth.JWTExpiryHours) * time.Hour).Unix(),
		Iss: "nido",
	})
	body := jwtHeader + "." + b64.EncodeToString(payload)
	return body + "." + sign(body)
}

func verifyToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != jwtHeader {
		return false
	}
	if !hmac.Equal([]byte(sign(parts[0]+"."+parts[1])), []byte(parts[2])) {
		return false
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var c claims
	if json.Unmarshal(payload, &c) != nil {
		return false
	}
	return (c.Iss == "nido" || c.Iss == "aura-home") && time.Now().Unix() < c.Exp
}

// ---------- límite de intentos por IP ----------

type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	locked   map[string]time.Time

	// Los intentos desde internet se cuentan además todos juntos: cambiar de
	// IP no sirve para seguir probando PIN.
	remoteFails []time.Time
	remoteLock  time.Time
}

const (
	remoteMaxFails = 10
	remoteWindow   = time.Hour
	remoteLockout  = time.Hour
)

// remoteLockedFor devuelve los segundos que queda pausado el login externo.
func (r *rateLimiter) remoteLockedFor() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return max(0, int(time.Until(r.remoteLock).Seconds()))
}

// registerRemote anota un login desde internet; true si acaba de pausarse.
func (r *rateLimiter) registerRemote(success bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if success {
		return false
	}
	now := time.Now()
	recent := r.remoteFails[:0]
	for _, t := range r.remoteFails {
		if now.Sub(t) < remoteWindow {
			recent = append(recent, t)
		}
	}
	r.remoteFails = append(recent, now)
	if len(r.remoteFails) >= remoteMaxFails {
		r.remoteFails = nil
		r.remoteLock = now.Add(remoteLockout)
		return true
	}
	return false
}

var limiter = &rateLimiter{attempts: map[string][]time.Time{}, locked: map[string]time.Time{}}

// lockedFor devuelve los segundos que le quedan de bloqueo a la IP (0 = libre).
func (r *rateLimiter) lockedFor(ip string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	until, ok := r.locked[ip]
	if !ok {
		return 0
	}
	if remaining := int(time.Until(until).Seconds()); remaining > 0 {
		return remaining
	}
	delete(r.locked, ip)
	delete(r.attempts, ip)
	return 0
}

// register anota un intento y devuelve true si la IP queda bloqueada.
func (r *rateLimiter) register(ip string, success bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if success {
		delete(r.attempts, ip)
		return false
	}
	now := time.Now()
	recent := r.attempts[ip][:0]
	for _, t := range r.attempts[ip] {
		if now.Sub(t) < 5*time.Minute {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	r.attempts[ip] = recent
	if len(recent) >= cfg.Auth.MaxAttempts {
		r.locked[ip] = now.Add(time.Duration(cfg.Auth.LockoutMinutes) * time.Minute)
		return true
	}
	return false
}
