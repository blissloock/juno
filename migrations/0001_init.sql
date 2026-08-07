-- Esquema inicial de Juno.
-- Se ejecuta automáticamente al arrancar el backend (ver db::ejecutar_migraciones).

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- =========================================================
-- Usuarios del dashboard (autenticación)
-- =========================================================
CREATE TABLE IF NOT EXISTS usuarios (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(50) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,        -- hash Argon2id, NUNCA texto plano
    rol             VARCHAR(20) NOT NULL DEFAULT 'lector', -- 'admin' | 'lector'
    creado_en       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ultimo_login    TIMESTAMPTZ
);

-- =========================================================
-- Flujos NetFlow (serie temporal, alto volumen de escritura)
-- =========================================================
CREATE TABLE IF NOT EXISTS flujos_netflow (
    tiempo          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_origen       INET NOT NULL,
    ip_destino      INET NOT NULL,
    puerto_origen   INTEGER,
    puerto_destino  INTEGER,
    protocolo       SMALLINT,
    bytes           BIGINT NOT NULL DEFAULT 0,
    paquetes        BIGINT NOT NULL DEFAULT 0
);
SELECT create_hypertable('flujos_netflow', 'tiempo', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS idx_netflow_ip_origen ON flujos_netflow (ip_origen, tiempo DESC);

-- =========================================================
-- Métricas SNMP (serie temporal)
-- =========================================================
CREATE TABLE IF NOT EXISTS metricas_snmp (
    tiempo      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    host        VARCHAR(255) NOT NULL,
    cpu_pct     REAL,
    ram_pct     REAL,
    interfaz    VARCHAR(100),
    trafico_in  BIGINT,
    trafico_out BIGINT
);
SELECT create_hypertable('metricas_snmp', 'tiempo', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS idx_snmp_host ON metricas_snmp (host, tiempo DESC);

-- =========================================================
-- Resultados de escaneos Nmap
-- =========================================================
CREATE TABLE IF NOT EXISTS escaneos_nmap (
    id                  SERIAL PRIMARY KEY,
    host                VARCHAR(255) NOT NULL,
    puertos_abiertos    JSONB NOT NULL DEFAULT '[]',
    so_detectado        VARCHAR(255),
    ejecutado_en        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_nmap_host ON escaneos_nmap (host, ejecutado_en DESC);

-- =========================================================
-- Alertas generadas por el sistema
-- =========================================================
CREATE TABLE IF NOT EXISTS alertas (
    id          SERIAL PRIMARY KEY,
    tipo        VARCHAR(50) NOT NULL,      -- 'netflow' | 'snmp' | 'nmap'
    severidad   VARCHAR(20) NOT NULL,      -- 'info' | 'advertencia' | 'critica'
    mensaje     TEXT NOT NULL,
    origen      VARCHAR(255),
    resuelta    BOOLEAN NOT NULL DEFAULT FALSE,
    creada_en   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alertas_no_resueltas ON alertas (resuelta, creada_en DESC);
