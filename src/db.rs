//! Módulo de acceso a datos (TimescaleDB / PostgreSQL)
//!
//! Nota de seguridad: TODAS las consultas usan parámetros ligados
//! ($1, $2, ...) vía `.bind()`. Nunca se concatena texto que venga del
//! usuario dentro del string SQL. Esto es lo que previene la inyección
//! SQL: el driver envía la consulta y los datos por separado al motor de
//! base de datos, que nunca "interpreta" los datos como parte del comando.
//!
//! Nota de modelado: los datos de monitoreo (NetFlow, SNMP, Nmap) viven en
//! una sola tabla tipo "colección" (`eventos`, ver migrations/0002_*.sql)
//! con una columna `datos JSONB`. Es un modelo tipo documento (como una
//! colección de Mongo) pero corriendo sobre Postgres/TimescaleDB, así que
//! seguimos usando el mismo pool, las mismas migraciones versionadas y las
//! mismas garantías transaccionales que ya teníamos. `usuarios` y `alertas`
//! se quedan relacionales a propósito (ver el comentario en la migración).

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
// Se queda relacional a propósito: el login necesita UNIQUE(username) y
// tipos estrictos; convertir esto a JSONB no aportaría nada y sí quitaría
// garantías (ver comentario en migrations/0002_documentos_json.sql).

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
// Eventos (colección JSONB: NetFlow / SNMP / Nmap)
// =====================================================================

/// Representa un documento tal cual sale de la tabla `eventos`.
/// `datos` es JSON libre: su forma depende de `tipo`.
#[derive(Debug, Serialize)]
pub struct Evento {
    pub id: i64,
    pub tiempo: DateTime<Utc>,
    pub tipo: String,
    pub origen: Option<String>,
    pub datos: serde_json::Value,
}

/// Inserta un documento nuevo en la colección `eventos`.
///
/// `tipo` identifica la "colección lógica" ('netflow' | 'snmp' | 'nmap'),
/// `origen` es el host/IP (se indexa aparte para consultas rápidas por
/// dispositivo), y `datos` es el documento JSON completo: puede tener
/// cualquier estructura, no hace falta migrar el esquema para agregar un
/// campo nuevo.
pub async fn insertar_evento(
    pool: &PgPool,
    tipo: &str,
    origen: Option<&str>,
    datos: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO eventos (tipo, origen, datos) VALUES ($1, $2, $3)")
        .bind(tipo)
        .bind(origen)
        .bind(datos)
        .execute(pool)
        .await?;
    Ok(())
}

/// Últimos N eventos de un tipo dado, para el dashboard.
/// Límite duro adicional: nunca se devuelven más de 1000 filas en una sola
/// respuesta, sin importar lo que pida el cliente.
pub async fn ultimos_eventos_por_tipo(
    pool: &PgPool,
    tipo: &str,
    limite: i64,
) -> Result<Vec<Evento>, sqlx::Error> {
    let filas = sqlx::query(
        "SELECT id, tiempo, tipo, origen, datos
         FROM eventos
         WHERE tipo = $1
         ORDER BY tiempo DESC
         LIMIT $2",
    )
    .bind(tipo)
    .bind(limite.clamp(1, 1000))
    .fetch_all(pool)
    .await?;

    Ok(filas
        .into_iter()
        .map(|f| Evento {
            id: f.get("id"),
            tiempo: f.get("tiempo"),
            tipo: f.get("tipo"),
            origen: f.get("origen"),
            datos: f.get("datos"),
        })
        .collect())
}

/// Últimos N eventos de un host/origen específico, sin importar el tipo.
/// Útil para la vista "Estado del dispositivo" del frontend.
pub async fn ultimos_eventos_por_origen(
    pool: &PgPool,
    origen: &str,
    limite: i64,
) -> Result<Vec<Evento>, sqlx::Error> {
    let filas = sqlx::query(
        "SELECT id, tiempo, tipo, origen, datos
         FROM eventos
         WHERE origen = $1
         ORDER BY tiempo DESC
         LIMIT $2",
    )
    .bind(origen)
    .bind(limite.clamp(1, 1000))
    .fetch_all(pool)
    .await?;

    Ok(filas
        .into_iter()
        .map(|f| Evento {
            id: f.get("id"),
            tiempo: f.get("tiempo"),
            tipo: f.get("tipo"),
            origen: f.get("origen"),
            datos: f.get("datos"),
        })
        .collect())
}

/// Busca eventos cuyo documento JSON contenga el filtro dado.
/// Ejemplo de uso desde main.rs: `datos @> {"puerto_destino": 443}` para
/// encontrar todos los flujos NetFlow hacia el puerto 443.
/// Esto es el equivalente directo a un `.find({...})` de Mongo.
pub async fn buscar_eventos_por_filtro_json(
    pool: &PgPool,
    tipo: &str,
    filtro: &serde_json::Value,
    limite: i64,
) -> Result<Vec<Evento>, sqlx::Error> {
    let filas = sqlx::query(
        "SELECT id, tiempo, tipo, origen, datos
         FROM eventos
         WHERE tipo = $1 AND datos @> $2
         ORDER BY tiempo DESC
         LIMIT $3",
    )
    .bind(tipo)
    .bind(filtro)
    .bind(limite.clamp(1, 1000))
    .fetch_all(pool)
    .await?;

    Ok(filas
        .into_iter()
        .map(|f| Evento {
            id: f.get("id"),
            tiempo: f.get("tiempo"),
            tipo: f.get("tipo"),
            origen: f.get("origen"),
            datos: f.get("datos"),
        })
        .collect())
}

// =====================================================================
// Alertas (se queda relacional: su forma no cambia y necesita filtrar
// rápido por "resuelta", algo que una columna normal hace mejor que JSONB)
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
