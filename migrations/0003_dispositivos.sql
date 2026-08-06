-- Migración 0003: catálogo de dispositivos monitoreados.
--
-- POR QUÉ esto es relacional y NO otro documento JSONB en `eventos`:
-- `eventos` es un historial de lecturas (alto volumen, forma variable por
-- tipo). `dispositivos` es lo opuesto: un catálogo PEQUEÑO con forma FIJA
-- -- el "maestro" de qué equipos existen y su último estado conocido.
-- Aquí sí importa un UNIQUE(ip) real (no se puede registrar la misma IP
-- dos veces) y updates puntuales por id, que es exactamente el tipo de
-- consistencia que Postgres relacional resuelve mejor que un documento.

CREATE TABLE IF NOT EXISTS dispositivos (
    id              SERIAL PRIMARY KEY,
    nombre          VARCHAR(100) NOT NULL,
    tipo            VARCHAR(50) NOT NULL,
    ip              VARCHAR(45) NOT NULL UNIQUE,
    estado          VARCHAR(20) NOT NULL DEFAULT 'offline', -- 'online' | 'warning' | 'offline'
    cpu_pct         REAL,
    ram_pct         REAL,
    temp_c          REAL,
    creado_en       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actualizado_en  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dispositivos_ip ON dispositivos (ip);
