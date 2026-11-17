#!/usr/bin/env bash
# Instala Nido como servicio systemd.
# Uso: sudo ./scripts/install.sh   (desde la carpeta nido-server)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta este script con sudo." >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN=/usr/local/bin/nido
ETC=/etc/nido

case "$(uname -m)" in
  x86_64)  ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo "Arquitectura no soportada: $(uname -m). Compila con: go build -o nido ." >&2; exit 1 ;;
esac

echo "==> Instalando binario ($ARCH)"
systemctl stop nido.service 2>/dev/null || true
install -m 755 "$SRC_DIR/dist/nido-linux-$ARCH" "$BIN"
mkdir -p "$ETC"
[[ -f "$ETC/config.yaml" ]] || cp "$SRC_DIR/config.yaml.example" "$ETC/config.yaml"

if [[ ! -f "$ETC/secrets.yaml" ]] || ! grep -q pin_hash "$ETC/secrets.yaml"; then
  echo "==> PIN de acceso para la app"
  "$BIN" --set-pin
fi

if ! grep -q router_password "$ETC/secrets.yaml" 2>/dev/null; then
  echo "==> Router (opcional, recomendado)"
  read -r -p "¿Leer los dispositivos conectados desde el panel web del router ZTE? [s/N] " answer
  if [[ "$answer" =~ ^[sS] ]]; then
    "$BIN" --set-router-password
    sed -i 's/^  type: ""/  type: zte/' "$ETC/config.yaml"
    "$BIN" --router-test || echo "El login en el router falló: revisa usuario/contraseña en $ETC/config.yaml"
  fi
fi

echo "==> Servicio systemd"
cp "$SRC_DIR/scripts/nido.service" /etc/systemd/system/nido.service
systemctl daemon-reload
systemctl enable --now nido.service

IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)
echo
echo "Listo. Nido escucha en https://${IP:-<ip-del-servidor>}:8443"
echo "Si usas firewall, abre 8443/tcp y 8444/udp solo para tu red local."
echo "Configuración: $ETC/config.yaml   Logs: journalctl -u nido -f"
