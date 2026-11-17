#!/usr/bin/env bash
# Construye y arranca el contenedor "nido". Uso: ./docker/run.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

mkdir -p data
[ -f data/config.yaml ] || cp config.yaml.example data/config.yaml

docker build -t nido-server .
docker rm -f nido 2>/dev/null || true
docker run -d --name nido --restart unless-stopped \
  --network=host \
  -v "$(pwd)/data:/etc/nido" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /:/host/root:ro \
  -v /home:/host/home:ro \
  nido-server

echo "Arrancado. Logs: docker logs -f nido"
echo "PIN de la app:           docker exec -it nido nido --set-pin"
echo "Contraseña del router:   docker exec -it nido nido --set-router-password"
echo "Aplicar cambios:         docker restart nido"
