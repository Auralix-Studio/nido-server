# Nido — servidor

Servicio en Go (un solo binario, sin dependencias) que corre en tu servidor
Linux de casa y expone una API HTTPS que usa la app [**nido**](https://github.com/Auralix-Studio/nido).

## Qué hace

- **Servidor**: CPU, RAM, swap, temperatura, discos, tráfico de red, uptime. Reinicio y apagado.
- **Servicios**: unidades systemd y contenedores Docker con estado, CPU, memoria, puertos y logs. Iniciar, detener y reiniciar.
- **Red**: quién está conectado, leído del **panel web del router** (ZTE) o, si no está configurado, con un escaneo ARP. Guarda cada dispositivo por su MAC: IP, nombre, WiFi/cable, primera y última vez visto.
- **Alertas**: dispositivo nuevo en la red, servicio fijado caído, intentos de PIN fallidos. Opcionalmente push al móvil por [ntfy](https://ntfy.sh).

## Despliegue con Docker (sin sudo)

```bash
./docker/run.sh
docker exec -it nido nido --set-pin
docker exec -it nido nido --set-router-password
```

La configuración y los secretos se guardan en `./data` (montado en `/etc/nido` dentro del contenedor) y los contenedores Docker del host se gestionan mediante `/var/run/docker.sock`.

## Instalación (Linux con systemd)

Copia esta carpeta al servidor y ejecuta:

```bash
sudo ./scripts/install.sh
```

Instala `/usr/local/bin/nido`, pide el PIN de 4 dígitos, pregunta si
quieres conectar el router y deja el servicio `nido` activo en el puerto
8443. Si usas firewall, abre `8443/tcp` y `8444/udp` solo para tu red local.

```bash
journalctl -u nido -f              # logs
sudo nano /etc/nido/config.yaml    # configuración
sudo nido --set-pin                # cambiar el PIN de la app
sudo systemctl restart nido        # aplicar cambios
```

## Leer los dispositivos desde el router

El servidor inicia sesión en el panel web del router igual que lo harías tú
desde el navegador, lee la lista de equipos conectados y cierra sesión.

```bash
sudo nido --set-router-password    # la contraseña se pide sin mostrarla
sudo nido --router-test            # un login de prueba: lista los equipos
```

En `/etc/nido/config.yaml` (o `data/config.yaml` con Docker) pon `router.type: zte` (y `username` si no es
`admin`) y reinicia el servicio.

- Probado con un ZTE F6600P real (firmware V9.1.10P2N23): da nombre, IP, WiFi o cable, señal (RSSI), red WiFi, puerto LAN y el estado del propio router (CPU, memoria, temperatura). Con otro modelo, `nido --router-test --raw` muestra lo que devuelve.
- `nido --router-explore` recorre todo el panel solo con lecturas y guarda cada endpoint en `data/router-dump` con un `INDEX.txt`. Ese volcado contiene las claves WiFi: no lo compartas.
- El router admite un solo administrador a la vez: mientras tengas su panel abierto en el navegador, la consulta puede fallar y el servidor usa el escaneo ARP en ese ciclo.
- Si el router rechaza la contraseña, el servidor deja de intentarlo 15 minutos para no bloquear el panel.
- La contraseña se guarda en `/etc/nido/secrets.yaml`, legible solo por root.

## Compilar

```bash
go test ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/nido-linux-amd64 .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/nido-linux-arm64 .
```

También funciona en Windows para pruebas (sin servicios systemd).

## Notas

- En modo systemd corre como root para controlar unidades systemd y leer sensores.
- El certificado es auto-firmado y el acceso es por PIN con bloqueo tras 5 fallos (y bloqueo global tras 10 fallos remotos desde Cloudflare). Si lo expones por un túnel de Cloudflare, configura la app con el subdominio en `REMOTE_HOST`.
- Los móviles modernos usan MAC aleatoria por red: ponles nombre desde la app.
- **Bloquear dispositivos**: desde la app se puede bloquear un equipo WiFi. El servidor añade su MAC al filtro MAC del router ("WLAN Avanzado") en cada red activa y pone esas redes en modo lista negra; desbloquear borra las reglas. Límites: solo WiFi (el firmware no filtra los puertos LAN), no toca el filtro si está en modo lista blanca, y un equipo con MAC aleatoria puede volver con otra dirección. `nido --router-write-test` comprueba que el router acepta cambios sin afectar a nadie.
