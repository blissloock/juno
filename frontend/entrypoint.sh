#!/bin/sh
set -e

# nginx corre en segundo plano; cloudflared queda como el proceso
# principal del contenedor (PID 1), así que un `docker stop` le manda la
# señal directamente a él. El trap se encarga de apagar nginx también
# cuando eso pase, para que el contenedor termine limpio.
nginx -g "daemon off;" &
NGINX_PID=$!

trap 'echo "Apagando..."; kill -TERM "$NGINX_PID" 2>/dev/null; exit 0' TERM INT

# Si todavía no han copiado las credenciales/config del túnel (ver
# cloudflared/config.yml y cloudflared/creds.json en el proyecto), el
# contenedor igual sirve el frontend en el puerto 80 localmente -- solo
# que sin túnel hacia afuera. Así no se rompe el desarrollo local por no
# tener Cloudflare configurado todavía.
if [ -f /etc/cloudflared/config.yml ] && [ -f /etc/cloudflared/creds.json ]; then
    echo "Config de Cloudflare Tunnel encontrada, iniciando túnel..."
    cloudflared tunnel --config /etc/cloudflared/config.yml run &
    CF_PID=$!
    wait "$CF_PID"
else
    echo "Aviso: no se encontró /etc/cloudflared/config.yml o creds.json -- el túnel no se inició. Solo sirviendo nginx en local (puerto 80)."
    wait "$NGINX_PID"
fi
