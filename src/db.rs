//! Módulo de acceso a datos (TimescaleDB / PostgreSQL)
//!
//! Nota de seguridad: TODAS las consultas usan parámetros ligados
//! ($1, $2, ...) vía `.bind()`. Nunca se concatena texto que venga del
//! usuario dentro del string SQL. Esto es lo que previene la inyección
//! SQL: el driver envía la consulta y los datos por separado al motor de
//! base de datos, que nunca "interpreta" los datos como parte del comando.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use std::env;
use std::time::Duration;

/// Crea y retorna un pool de conexiones a la base de datos.
pub async fn crear_pool() -> Result<PgPool, sqlx::Error> {
    let database_url = env::var("DATABASE_URL")
        .expect("La variable de entorno DATABASE_URL no está definida");

    log::info!("Conectando a la base de datos...");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        // Evita que una conexión colgada bloquee el pool para siempre.
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await?;

    log::info!("Conexión a la base de datos establecida correctamente.");

    Ok(pool)
}

/// Ejecuta las migraciones embebidas en `./migrations` al arrancar la app,
/// así el esquema siempre queda sincronizado con el código sin pasos
/// manuales ("acuérdate de correr este script antes de levantar todo").
pub async fn ejecutar_migraciones(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    log::info!("Aplicando migraciones...");
    sqlx::migrate!("./migrations").run(pool).await?;
    log::info!("Migraciones aplicadas correctamente.");
    Ok(())
}

// =====================================================================
// Usuarios / autenticación
// =====================================================================

#[derive(Debug, Serialize)]
pub struct Usuario {
    pub id: i32,
    pub username: String,
    #[serde(skip_serializing)] // nunca debe salir en una respuesta JSON
    pub password_hash: String,
    pub rol: String,
}

/// Busca un usuario por su username.
///
/// Importante: el handler de login (en main.rs) debe responder el MISMO
/// mensaje genérico tanto si el usuario no existe como si la contraseña
/// es incorrecta. Distinguir esos dos casos en la respuesta le regala a
/// un atacante la posibilidad de enumerar usuarios válidos uno por uno.
pub async fn obtener_usuario_por_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<Usuario>, sqlx::Error> {
    let fila = sqlx::query(
        "SELECT id, username, password_hash, rol FROM usuarios WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(fila.map(|f| Usuario {
        id: f.get("id"),
        username: f.get("username"),
        password_hash: f.get("password_hash"),
        rol: f.get("rol"),
    }))
}

/// Crea un usuario nuevo. `password_hash` debe venir YA calculado con
/// Argon2id (ver `auth::hash_password`) -- este módulo nunca debe recibir
/// ni guardar una contraseña en texto plano.
pub async fn crear_usuario(
    pool: &PgPool,
    username: &str,
    password_hash: &str,
    rol: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO usuarios (username, password_hash, rol) VALUES ($1, $2, $3)")
        .bind(username)
        .bind(password_hash)
        .bind(rol)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn actualizar_ultimo_login(pool: &PgPool, usuario_id: i32) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE usuarios SET ultimo_login = NOW() WHERE id = $1")
        .bind(usuario_id)
        .execute(pool)
        .await?;
    Ok(())
}

// =====================================================================
// Flujos NetFlow
// =====================================================================

pub struct NuevoFlujoNetflow {
    pub ip_origen: String,
    pub ip_destino: String,
    pub puerto_origen: Option<i32>,
    pub puerto_destino: Option<i32>,
    pub protocolo: Option<i16>,
    pub bytes: i64,
    pub paquetes: i64,
}

pub async fn insertar_flujo_netflow(
    pool: &PgPool,
    flujo: &NuevoFlujoNetflow,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO flujos_netflow
            (ip_origen, ip_destino, puerto_origen, puerto_destino, protocolo, bytes, paquetes)
         VALUES ($1::inet, $2::inet, $3, $4, $5, $6, $7)",
    )
    .bind(&flujo.ip_origen)
    .bind(&flujo.ip_destino)
    .bind(flujo.puerto_origen)
    .bind(flujo.puerto_destino)
    .bind(flujo.protocolo)
    .bind(flujo.bytes)
    .bind(flujo.paquetes)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct FlujoNetflow {
    pub tiempo: DateTime<Utc>,
    pub ip_origen: String,
    pub ip_destino: String,
    pub bytes: i64,
}

/// Últimos N flujos, para el dashboard.
pub async fn ultimos_flujos(pool: &PgPool, limite: i64) -> Result<Vec<FlujoNetflow>, sqlx::Error> {
    let filas = sqlx::query(
        "SELECT tiempo, ip_origen::text, ip_destino::text, bytes
         FROM flujos_netflow ORDER BY tiempo DESC LIMIT $1",
    )
    // Límite duro adicional: sin importar lo que pida el cliente, nunca
    // se devuelven más de 1000 filas en una sola respuesta (protege
    // memoria/ancho de banda contra un parámetro abusivo).
    .bind(limite.clamp(1, 1000))
    .fetch_all(pool)
    .await?;

    Ok(filas
        .into_iter()
        .map(|f| FlujoNetflow {
            tiempo: f.get("tiempo"),
            ip_origen: f.get("ip_origen"),
            ip_destino: f.get("ip_destino"),
            bytes: f.get("bytes"),
        })
        .collect())
}

// =====================================================================
// Métricas SNMP
// =====================================================================

pub async fn insertar_metrica_snmp(
    pool: &PgPool,
    host: &str,
    cpu_pct: f32,
    ram_pct: f32,
    interfaz: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO metricas_snmp (host, cpu_pct, ram_pct, interfaz) VALUES ($1, $2, $3, $4)",
    )
    .bind(host)
    .bind(cpu_pct)
    .bind(ram_pct)
    .bind(interfaz)
    .execute(pool)
    .await?;
    Ok(())
}

// =====================================================================
// Escaneos Nmap
// =====================================================================

pub async fn insertar_escaneo_nmap(
    pool: &PgPool,
    host: &str,
    puertos_abiertos: &serde_json::Value,
    so_detectado: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO escaneos_nmap (host, puertos_abiertos, so_detectado) VALUES ($1, $2, $3)",
    )
    .bind(host)
    .bind(puertos_abiertos)
    .bind(so_detectado)
    .execute(pool)
    .await?;
    Ok(())
}

// =====================================================================
// Alertas
// =====================================================================

pub async fn crear_alerta(
    pool: &PgPool,
    tipo: &str,
    severidad: &str,
    mensaje: &str,
    origen: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO alertas (tipo, severidad, mensaje, origen) VALUES ($1, $2, $3, $4)")
        .bind(tipo)
        .bind(severidad)
        .bind(mensaje)
        .bind(origen)
        .execute(pool)
        .await?;
    Ok(())
}
