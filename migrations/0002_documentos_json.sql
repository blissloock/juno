-- Migración 0002: modelo tipo documento (JSONB) para los datos de monitoreo.
--
-- POR QUÉ este enfoque y no una base NoSQL aparte (ej. MongoDB):
-- Postgres + TimescaleDB ya nos dan pooling async (sqlx), transacciones,
-- migraciones versionadas y particionado automático por tiempo. Cambiar de
-- motor implicaría un contenedor más en docker-compose.yml, otra librería
-- cliente, y perder las garantías ACID que ya usamos en usuarios/alertas.
-- JSONB nos da lo que realmente necesitábamos de "NoSQL": esquema flexible
-- por evento (cada tipo de dato guarda los campos que le hacen falta, sin
-- migraciones nuevas cada vez que se agrega un campo), sin sacrificar nada
-- de la infraestructura que ya funciona.
--
-- QUÉ CAMBIA:
-- flujos_netflow, metricas_snmp y escaneos_nmap se reemplazan por una sola
-- tabla "eventos": cada fila es un documento (columna `datos JSONB`) con un
-- `tipo` que dice qué representa. Es el equivalente a tener 3 "colecciones"
-- de Mongo, pero en una sola hypertable de Timescale.
--
-- `usuarios` y `alertas` NO se tocan: usuarios necesita UNIQUE(username) e
-- índices confiables por temas de seguridad de login; alertas se queda
-- relacional porque su forma no cambia (tipo/severidad/mensaje) y necesita
-- filtrar rápido por "resuelta", algo que JSONB no hace mejor que una
-- columna normal.

-- =========================================================
-- Colección de eventos de monitoreo (NetFlow / SNMP / Nmap)
-- =========================================================
CREATE TABLE IF NOT EXISTS eventos (
    id          BIGSERIAL,
    tiempo      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tipo        VARCHAR(30) NOT NULL,   -- 'netflow' | 'snmp' | 'nmap'
    origen      VARCHAR(255),           -- host/IP que generó el evento (opcional pero indexado)
    datos       JSONB NOT NULL,         -- el "documento": estructura libre según `tipo`
    PRIMARY KEY (id, tiempo)
);

-- Hypertable: mismo particionado automático por tiempo que ya usaban las
-- tablas anteriores.
SELECT create_hypertable('eventos', 'tiempo', if_not_exists => TRUE);

-- Índice para las consultas más comunes del dashboard: "dame los últimos
-- eventos de tipo X" y "dame los eventos de este host".
CREATE INDEX IF NOT EXISTS idx_eventos_tipo_tiempo ON eventos (tipo, tiempo DESC);
CREATE INDEX IF NOT EXISTS idx_eventos_origen ON eventos (origen, tiempo DESC);

-- Índice GIN: permite filtrar DENTRO del JSON (ej. WHERE datos->>'ip_origen'
-- = '192.168.1.1' o WHERE datos @> '{"puerto_destino": 443}') con buen
-- rendimiento, igual que un índice de campo en una colección de Mongo.
CREATE INDEX IF NOT EXISTS idx_eventos_datos_gin ON eventos USING GIN (datos jsonb_path_ops);

-- =========================================================
-- Migración de datos existentes (si las tablas viejas tenían filas)
-- =========================================================
INSERT INTO eventos (tiempo, tipo, origen, datos)
SELECT
    tiempo,
    'netflow',
    ip_origen::text,
    jsonb_build_object(
        'ip_origen', ip_origen::text,
        'ip_destino', ip_destino::text,
        'puerto_origen', puerto_origen,
        'puerto_destino', puerto_destino,
        'protocolo', protocolo,
        'bytes', bytes,
        'paquetes', paquetes
    )
FROM flujos_netflow
ON CONFLICT DO NOTHING;

INSERT INTO eventos (tiempo, tipo, origen, datos)
SELECT
    tiempo,
    'snmp',
    host,
    jsonb_build_object(
        'host', host,
        'cpu_pct', cpu_pct,
        'ram_pct', ram_pct,
        'interfaz', interfaz,
        'trafico_in', trafico_in,
        'trafico_out', trafico_out
    )
FROM metricas_snmp
ON CONFLICT DO NOTHING;

INSERT INTO eventos (tiempo, tipo, origen, datos)
SELECT
    ejecutado_en,
    'nmap',
    host,
    jsonb_build_object(
        'host', host,
        'puertos_abiertos', puertos_abiertos,
        'so_detectado', so_detectado
    )
FROM escaneos_nmap
ON CONFLICT DO NOTHING;

-- Las tablas viejas se dejan (no se hace DROP) por si necesitan comparar o
-- revertir. Cuando confirmen que "eventos" funciona bien en el dashboard,
-- pueden correr un DROP TABLE manual de flujos_netflow / metricas_snmp /
-- escaneos_nmap en una migración 0003 aparte.
