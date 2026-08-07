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
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
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

/// Últimas N alertas, más recientes primero. Para el panel de alertas
/// del dashboard.
pub async fn listar_alertas(pool: &PgPool, limite: i64) -> Result<Vec<Alerta>, sqlx::Error> {
    let filas = sqlx::query(
        "SELECT id, tipo, severidad, mensaje, origen, resuelta, creada_en
         FROM alertas
         ORDER BY creada_en DESC
         LIMIT $1",
    )
    .bind(limite.clamp(1, 500))
    .fetch_all(pool)
    .await?;

    Ok(filas
        .into_iter()
        .map(|f| Alerta {
            id: f.get("id"),
            tipo: f.get("tipo"),
            severidad: f.get("severidad"),
            mensaje: f.get("mensaje"),
            origen: f.get("origen"),
            resuelta: f.get("resuelta"),
            creada_en: f.get("creada_en"),
        })
        .collect())
}

#[derive(Debug, Serialize)]
pub struct Alerta {
    pub id: i32,
    pub tipo: String,
    pub severidad: String,
    pub mensaje: String,
    pub origen: Option<String>,
    pub resuelta: bool,
    pub creada_en: DateTime<Utc>,
}

// =====================================================================
// Dispositivos (catálogo de equipos monitoreados, ver migrations/0003_*)
// =====================================================================
// Se queda relacional a propósito -- ver el comentario en la migración.
// A diferencia de `eventos` (historial), aquí sí necesitamos UNIQUE(ip) e
// integridad al hacer UPDATE/DELETE por id.

#[derive(Debug, Serialize)]
pub struct Dispositivo {
    pub id: i32,
    pub nombre: String,
    pub tipo: String,
    pub ip: String,
    pub estado: String,
    pub cpu_pct: Option<f32>,
    pub ram_pct: Option<f32>,
    pub temp_c: Option<f32>,
    pub actualizado_en: DateTime<Utc>,
}

fn fila_a_dispositivo(f: PgRow) -> Dispositivo {
    Dispositivo {
        id: f.get("id"),
        nombre: f.get("nombre"),
        tipo: f.get("tipo"),
        ip: f.get("ip"),
        estado: f.get("estado"),
        cpu_pct: f.get("cpu_pct"),
        ram_pct: f.get("ram_pct"),
        temp_c: f.get("temp_c"),
        actualizado_en: f.get("actualizado_en"),
    }
}

pub async fn listar_dispositivos(pool: &PgPool) -> Result<Vec<Dispositivo>, sqlx::Error> {
    let filas = sqlx::query(
        "SELECT id, nombre, tipo, ip, estado, cpu_pct, ram_pct, temp_c, actualizado_en
         FROM dispositivos
         ORDER BY nombre ASC",
    )
    .fetch_all(pool)
    .await?;

    Ok(filas.into_iter().map(fila_a_dispositivo).collect())
}

pub async fn obtener_dispositivo(pool: &PgPool, id: i32) -> Result<Option<Dispositivo>, sqlx::Error> {
    let fila = sqlx::query(
        "SELECT id, nombre, tipo, ip, estado, cpu_pct, ram_pct, temp_c, actualizado_en
         FROM dispositivos WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(fila.map(fila_a_dispositivo))
}

pub async fn crear_dispositivo(
    pool: &PgPool,
    nombre: &str,
    tipo: &str,
    ip: &str,
) -> Result<Dispositivo, sqlx::Error> {
    let fila = sqlx::query(
        "INSERT INTO dispositivos (nombre, tipo, ip)
         VALUES ($1, $2, $3)
         RETURNING id, nombre, tipo, ip, estado, cpu_pct, ram_pct, temp_c, actualizado_en",
    )
    .bind(nombre)
    .bind(tipo)
    .bind(ip)
    .fetch_one(pool)
    .await?;

    Ok(fila_a_dispositivo(fila))
}

pub async fn actualizar_dispositivo(
    pool: &PgPool,
    id: i32,
    nombre: &str,
    tipo: &str,
    ip: &str,
) -> Result<Option<Dispositivo>, sqlx::Error> {
    let fila = sqlx::query(
        "UPDATE dispositivos SET nombre = $1, tipo = $2, ip = $3, actualizado_en = NOW()
         WHERE id = $4
         RETURNING id, nombre, tipo, ip, estado, cpu_pct, ram_pct, temp_c, actualizado_en",
    )
    .bind(nombre)
    .bind(tipo)
    .bind(ip)
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(fila.map(fila_a_dispositivo))
}

pub async fn eliminar_dispositivo(pool: &PgPool, id: i32) -> Result<bool, sqlx::Error> {
    let resultado = sqlx::query("DELETE FROM dispositivos WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(resultado.rows_affected() > 0)
}

pub async fn eliminar_dispositivos_masivo(pool: &PgPool, ids: &[i32]) -> Result<u64, sqlx::Error> {
    let resultado = sqlx::query("DELETE FROM dispositivos WHERE id = ANY($1)")
        .bind(ids)
        .execute(pool)
        .await?;
    Ok(resultado.rows_affected())
}

pub async fn eliminar_dispositivos_offline(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let resultado = sqlx::query("DELETE FROM dispositivos WHERE estado = 'offline'")
        .execute(pool)
        .await?;
    Ok(resultado.rows_affected())
}

#[derive(Debug, Serialize)]
pub struct PuntosTraficoNetflow {
    pub hora: String,
    pub cantidad_flujos: i64,
}

#[derive(Debug, Serialize)]
pub struct HostNetflowTop {
    pub origen: String,
    pub flujos: i64,
}

#[derive(Debug, Serialize)]
pub struct EstadisticasNetflow {
    pub serie_tiempo: Vec<PuntosTraficoNetflow>,
    pub top_hosts: Vec<HostNetflowTop>,
    pub total_flujos: i64,
    pub entropia_red: f64,
}

pub async fn obtener_estadisticas_netflow(pool: &PgPool) -> Result<EstadisticasNetflow, sqlx::Error> {
    let filas_serie = sqlx::query(
        "SELECT to_char(date_trunc('minute', tiempo), 'HH24:MI') as hora, COUNT(*) as cantidad
         FROM eventos
         WHERE tipo = 'netflow' AND tiempo >= NOW() - INTERVAL '1 hour'
         GROUP BY date_trunc('minute', tiempo)
         ORDER BY date_trunc('minute', tiempo) ASC",
    )
    .fetch_all(pool)
    .await?;

    let serie_tiempo = filas_serie
        .into_iter()
        .map(|f| PuntosTraficoNetflow {
            hora: f.get("hora"),
            cantidad_flujos: f.get("cantidad"),
        })
        .collect::<Vec<_>>();

    let filas_hosts = sqlx::query(
        "SELECT COALESCE(origen, 'Desconocido') as origen, COUNT(*) as flujos
         FROM eventos
         WHERE tipo = 'netflow'
         GROUP BY origen
         ORDER BY flujos DESC
         LIMIT 5",
    )
    .fetch_all(pool)
    .await?;

    let top_hosts = filas_hosts
        .into_iter()
        .map(|f| HostNetflowTop {
            origen: f.get("origen"),
            flujos: f.get("flujos"),
        })
        .collect::<Vec<_>>();

    let fila_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM eventos WHERE tipo = 'netflow'")
        .fetch_one(pool)
        .await?;

    let total_flujos = fila_total.0;

    let mut entropia = 0.0f64;
    if total_flujos > 0 {
        let filas_distribucion = sqlx::query(
            "SELECT COUNT(*) as flujos FROM eventos WHERE tipo = 'netflow' GROUP BY origen",
        )
        .fetch_all(pool)
        .await?;

        for f in filas_distribucion {
            let flujos: i64 = f.get("flujos");
            let p = flujos as f64 / total_flujos as f64;
            if p > 0.0 {
                entropia -= p * p.log2();
            }
        }
    }

    Ok(EstadisticasNetflow {
        serie_tiempo,
        top_hosts,
        total_flujos,
        entropia_red: (entropia * 100.0).round() / 100.0,
    })
}

/// Actualiza solo el estado de un dispositivo (usado tras un ping).
/// `cpu_pct`/`ram_pct`/`temp_c` no se tocan aquí porque ese dato viene de
/// SNMP, no de un ping -- ver snmp.rs para esa parte.
pub async fn actualizar_estado_dispositivo(
    pool: &PgPool,
    id: i32,
    estado: &str,
) -> Result<Option<Dispositivo>, sqlx::Error> {
    let fila = sqlx::query(
        "UPDATE dispositivos SET estado = $1, actualizado_en = NOW()
         WHERE id = $2
         RETURNING id, nombre, tipo, ip, estado, cpu_pct, ram_pct, temp_c, actualizado_en",
    )
    .bind(estado)
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(fila.map(fila_a_dispositivo))
}

/// Actualiza cpu_pct/ram_pct de un dispositivo ya registrado, identificado
/// por su IP (así es como lo referencian tanto SNMP_HOSTS como el catálogo
/// `dispositivos`). Usa COALESCE para no pisar con NULL un valor que ya
/// teníamos si esta lectura en particular no trajo ese dato. No falla si
/// la IP no está en el catálogo todavía (SNMP puede estar corriendo
/// contra un host que aún no se agregó manualmente ni se descubrió con
/// Nmap) -- en ese caso simplemente no hay fila que actualizar.
pub async fn actualizar_metricas_dispositivo(
    pool: &PgPool,
    ip: &str,
    cpu_pct: Option<f32>,
    ram_pct: Option<f32>,
) -> Result<Option<Dispositivo>, sqlx::Error> {
    let fila = sqlx::query(
        "UPDATE dispositivos
         SET cpu_pct = COALESCE($1, cpu_pct),
             ram_pct = COALESCE($2, ram_pct),
             actualizado_en = NOW()
         WHERE ip = $3
         RETURNING id, nombre, tipo, ip, estado, cpu_pct, ram_pct, temp_c, actualizado_en",
    )
    .bind(cpu_pct)
    .bind(ram_pct)
    .bind(ip)
    .fetch_optional(pool)
    .await?;

    Ok(fila.map(fila_a_dispositivo))
}

