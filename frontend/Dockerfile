FROM nginx:alpine

# Instala cloudflared (binario estático, sin dependencias raras) para
# poder correr el túnel en el MISMO contenedor que sirve el frontend --
# así todo lo que da la cara al público (nginx + túnel) viaja junto como
# una sola imagen. Al mover esta imagen a otro equipo no hace falta un
# segundo contenedor ni reconfigurar nada de red entre servicios.
RUN apk add --no-cache curl && \
    ARCH=$(uname -m) && \
    case "$ARCH" in \
        x86_64) CF_ARCH="amd64" ;; \
        aarch64) CF_ARCH="arm64" ;; \
        *) echo "Arquitectura no soportada: $ARCH" && exit 1 ;; \
    esac && \
    curl -fL -o /usr/local/bin/cloudflared \
        "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}" && \
    chmod +x /usr/local/bin/cloudflared && \
    apk del curl

# El HTML/CSS/JS quedan HORNEADOS dentro de la imagen (COPY, no un volumen
# montado desde el host como tenía antes docker-compose.yml) -- así, al
# mover esta imagen a otra máquina, el frontend viaja completo sin
# depender de que exista una carpeta "./frontend" en el nuevo host.
COPY index.html style.css script.js /usr/share/nginx/html/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
