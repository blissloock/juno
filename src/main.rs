use juno::{alerts, auth, db, ids, netflow, nmap, ping, snmp};

use actix_cors::Cors;
use actix_web::{http, middleware, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    log::info!("Iniciando Backend de Juno...");

    // 1. Conexión a la base de datos.
    let pool = db::crear_pool()
        .await
        .expect("No fue posible conectar a la base de datos. Verifica DATABASE_URL.");

    // 2. Migraciones: crean/actualizan las tablas automáticamente al
    //    arrancar. Así nadie del equipo tiene que acordarse de correr un
    //    script SQL a mano antes de levantar el backend.
    db::ejecutar_migraciones(&pool)
        .await
        .expect("No fue posible aplicar las migraciones de la base de datos.");

    // 3. Sonda NetFlow en segundo plano.
    let pool_netflow = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = netflow::iniciar_sonda_netflow(pool_netflow).await {
            log::error!("Error crítico en la sonda NetFlow: {}", e);
        }
    });

    // 4. Monitor SNMP en segundo plano (activo solo si SNMP_HOSTS está
    //    configurada; si no, se queda inactivo y lo avisa en el log).
    let pool_snmp = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = snmp::iniciar_monitor_snmp(pool_snmp).await {
            log::error!("Error crítico en el monitor SNMP: {}", e);
        }
    });

    // 5. Escáner Nmap periódico en segundo plano (opcional, activo solo
    //    si NMAP_HOSTS está configurada). El escaneo bajo demanda desde
    //    el frontend usa el endpoint POST /api/nmap/escanear, no este loop.
    let pool_nmap = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = nmap::iniciar_escaner_nmap(pool_nmap).await {
            log::error!("Error crítico en el escáner Nmap periódico: {}", e);
        }
    });

    let puerto: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    // 6. Monitor de anomalías de red (entropía NetFlow) en segundo plano.
    let pool_ids = pool.clone();
    tokio::spawn(async move {
    if let Err(e) = ids::iniciar_monitor_entropia(pool_ids).await {
        log::error!("Error crítico en el monitor de entropía NetFlow: {}", e);
    }
        });

    // El origen permitido para CORS sale de una variable de entorno.
    // Acepta VARIOS orígenes separados por coma (ej.
    // "http://localhost,http://192.168.1.50") para poder entrar tanto por
    // localhost como por la IP de la máquina en la red local sin tener
    // que elegir uno solo. IMPORTANTE: nunca usar Cors::permissive() en
    // producción, eso deja la API abierta a que cualquier sitio web la
    // consuma con las credenciales del usuario que la esté visitando.
    let frontend_origins: Vec<String> = std::env::var("FRONTEND_ORIGIN")
        .unwrap_or_else(|_| "http://localhost".to_string())
        .split(',')
        .map(|o| o.trim().to_string())
        .filter(|o| !o.is_empty())
        .collect();

    log::info!("Arrancando servidor web en http://0.0.0.0:{}", puerto);
    log::info!("CORS restringido a orígenes: {:?}", frontend_origins);

    HttpServer::new(move || {
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::CONTENT_TYPE])
            .max_age(3600);
        for origen in &frontend_origins {
            cors = cors.allowed_origin(origen);
        }

        App::new()
            .app_data(web::Data::new(pool.clone()))
            // Límite de tamaño del body JSON: evita que alguien mande un
            // payload gigante para agotar memoria (vector básico de DoS).
            .app_data(web::JsonConfig::default().limit(1024 * 64))
            .wrap(cors)
            // Cabeceras de seguridad estándar en cada respuesta.
            .wrap(
                middleware::DefaultHeaders::new()
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("Referrer-Policy", "no-referrer")),
            )
            .wrap(middleware::Logger::default())
            .route("/", web::get().to(index))
            .route("/health", web::get().to(health))
            .route("/auth/login", web::post().to(login))
            // Ejemplo de ruta YA protegida con JWT (ver el parámetro
            // `usuario: auth::AuthenticatedUser` en el handler `perfil`).
            .route("/api/perfil", web::get().to(perfil))
            // Consulta genérica de la colección JSONB `eventos`, para que
            // el dashboard pida NetFlow / SNMP / Nmap desde un solo
            // endpoint. Protegido con JWT igual que /api/perfil.
            .route("/api/eventos", web::get().to(listar_eventos))
            // Dispara un escaneo Nmap bajo demanda contra un host. Es lo
            // que debería llamar el botón "Escanear Dispositivo (Auto)"
            // del frontend. Protegido con JWT: escanear una IP arbitraria
            // no debe estar disponible sin autenticación.
            .route("/api/nmap/escanear", web::post().to(escanear_nmap))
            // Descubrimiento automático: escanea un rango CIDR completo y
            // agrega como dispositivo cualquier host nuevo que responda.
            .route("/api/nmap/descubrir", web::post().to(descubrir_red))
            // CRUD del catálogo de dispositivos (ver migrations/0003_*).
            .route("/api/dispositivos", web::get().to(listar_dispositivos))
            .route("/api/dispositivos", web::post().to(crear_dispositivo))
            .route("/api/dispositivos/eliminar-masivo", web::post().to(eliminar_dispositivos_masivo))
            .route("/api/dispositivos/limpiar-inactivos", web::post().to(limpiar_dispositivos_inactivos))
            .route("/api/dispositivos/{id}", web::put().to(actualizar_dispositivo))
            .route("/api/dispositivos/{id}", web::delete().to(eliminar_dispositivo))
            // Ping real a un dispositivo ya registrado: actualiza su
            // estado en la base de datos y genera una alerta automática
            // si hubo un cambio (ej. online -> offline).
            .route("/api/dispositivos/{id}/ping", web::post().to(ping_dispositivo))
            // Lectura del historial de alertas
            .route("/api/alertas", web::get().to(listar_alertas))
            // Gráficas y estadísticas de NetFlow / Entropía de Red
            .route("/api/netflow/grafica", web::get().to(grafica_netflow))
    })
    .bind(("0.0.0.0", puerto))?
    .run()
    .await
}

async fn index() -> impl Responder {
    HttpResponse::Ok().body("API de Monitoreo activa. Sonda NetFlow escuchando en segundo plano.")
}

async fn health(pool: web::Data<sqlx::PgPool>) -> impl Responder {
    match sqlx::query("SELECT 1").execute(pool.get_ref()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "status": "ok" })),
        Err(e) => {
            log::error!("Health check falló: {}", e);
            HttpResponse::ServiceUnavailable().json(serde_json::json!({ "status": "db_error" }))
        }
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

/// Login: valida credenciales y devuelve un JWT.
async fn login(pool: web::Data<sqlx::PgPool>, datos: web::Json<LoginRequest>) -> impl Responder {
    let usuario = match db::obtener_usuario_por_username(&pool, &datos.username).await {
        Ok(Some(u)) => u,
        // Mismo mensaje genérico si el usuario no existe o si la
        // contraseña es incorrecta: no le regalamos a un atacante la
        // posibilidad de enumerar usuarios válidos.
        Ok(None) => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": "Usuario o contraseña incorrectos" }))
        }
        Err(e) => {
            log::error!("Error consultando usuario: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Error interno" }));
        }
    };

    if !auth::verificar_password(&datos.password, &usuario.password_hash) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "Usuario o contraseña incorrectos" }));
    }

    let _ = db::actualizar_ultimo_login(&pool, usuario.id).await;

   match auth::generar_token(usuario.id, &usuario.rol) {
    Ok(token) => HttpResponse::Ok().json(serde_json::json!({ "token": token, "rol": usuario.rol })),
        Err(e) => {
            log::error!("Error generando token: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Error interno" }))
        }
    }
}

/// Ejemplo de endpoint protegido: si no viene un JWT válido, Actix nunca
/// llega a ejecutar el cuerpo de esta función.
async fn perfil(usuario: auth::AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "usuario_id": usuario.usuario_id,
        "rol": usuario.rol,
    }))
}

#[derive(Deserialize)]
struct EventosQuery {
    /// 'netflow' | 'snmp' | 'nmap'. Si se omite, hay que pasar `origen`.
    tipo: Option<String>,
    /// Filtra por host/IP en vez de por tipo (o junto con tipo).
    origen: Option<String>,
    /// Cuántos documentos devolver (se limita a 1000 en db.rs de todas formas).
    limite: Option<i64>,
}

/// Consulta genérica sobre la colección `eventos` (JSONB). Ejemplos:
///   GET /api/eventos?tipo=netflow&limite=50
///   GET /api/eventos?origen=192.168.1.1
async fn listar_eventos(
    pool: web::Data<sqlx::PgPool>,
    query: web::Query<EventosQuery>,
    _usuario: auth::AuthenticatedUser,
) -> impl Responder {
    let limite = query.limite.unwrap_or(100);

    let resultado = match (&query.tipo, &query.origen) {
        (_, Some(origen)) => db::ultimos_eventos_por_origen(&pool, origen, limite).await,
        (Some(tipo), None) => db::ultimos_eventos_por_tipo(&pool, tipo, limite).await,
        (None, None) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": "Debes indicar 'tipo' u 'origen'" }))
        }
    };

    match resultado {
        Ok(eventos) => HttpResponse::Ok().json(eventos),
        Err(e) => {
            log::error!("Error consultando eventos: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Error interno" }))
        }
    }
}

#[derive(Deserialize)]
struct EscanearRequest {
    host: String,
}

/// Dispara un escaneo Nmap bajo demanda. El resultado ya queda guardado
/// en `eventos` (vía nmap::escanear_host) y además se regresa directo en
/// la respuesta para que el frontend pueda llenar los campos "Auto" del
/// formulario sin tener que hacer una segunda consulta.
async fn escanear_nmap(
    pool: web::Data<sqlx::PgPool>,
    datos: web::Json<EscanearRequest>,
    usuario: auth::AuthenticatedUser,
) -> impl Responder {
    if let Err(resp) = usuario.exigir_admin() {
    return resp;
    }
    match nmap::escanear_host(&pool, &datos.host).await {
        Ok(resultado) => HttpResponse::Ok().json(resultado),
        Err(e) => {
            log::error!("Error en escaneo Nmap contra {}: {}", datos.host, e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }))
        }
    }
}

#[derive(Deserialize)]
struct DescubrirRequest {
    /// Rango en notación CIDR, ej. "192.168.1.0/24". Si se omite, se usa
    /// la variable de entorno NETWORK_CIDR (si está definida).
    red: Option<String>,
}

/// Escanea un rango de red completo y agrega automáticamente los
/// dispositivos nuevos que respondan. Ver `nmap::descubrir_red`.
async fn descubrir_red(
    pool: web::Data<sqlx::PgPool>,
    datos: web::Json<DescubrirRequest>,
    usuario: auth::AuthenticatedUser,
) -> impl Responder {
    if let Err(resp) = usuario.exigir_admin() {
    return resp;
    }
    let red = datos
        .red
        .clone()
        .filter(|r| !r.trim().is_empty())
        .or_else(|| std::env::var("NETWORK_CIDR").ok());

    let red = match red {
        Some(r) => r,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Indica 'red' (ej. \"192.168.1.0/24\") o configura NETWORK_CIDR"
            }))
        }
    };

    match nmap::descubrir_red(&pool, &red).await {
        Ok(resultado) => HttpResponse::Ok().json(resultado),
        Err(e) => {
            log::error!("Error en descubrimiento de red sobre {}: {}", red, e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e }))
        }
    }
}

// =====================================================================
// Dispositivos (catálogo)
// =====================================================================

#[derive(Deserialize)]
struct DispositivoRequest {
    nombre: String,
    tipo: String,
    ip: String,
}

async fn listar_dispositivos(
    pool: web::Data<sqlx::PgPool>,
    _usuario: auth::AuthenticatedUser,
) -> impl Responder {
    match db::listar_dispositivos(&pool).await {
        Ok(lista) => HttpResponse::Ok().json(lista),
        Err(e) => {
            log::error!("Error listando dispositivos: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Error interno" }))
        }
    }
}

async fn crear_dispositivo(
    pool: web::Data<sqlx::PgPool>,
    datos: web::Json<DispositivoRequest>,
    usuario: auth::AuthenticatedUser,
) -> impl Responder {
    if let Err(resp) = usuario.exigir_admin() {
    return resp;
}
    match db::crear_dispositivo(&pool, &datos.nombre, &datos.tipo, &datos.ip).await {
        Ok(d) => HttpResponse::Created().json(d),
        Err(e) => {
            // El caso más común aquí es violar UNIQUE(ip): dos
            // dispositivos no pueden compartir la misma IP.
            log::warn!("Error creando dispositivo: {}", e);
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No se pudo crear el dispositivo (¿la IP ya está registrada?)"
            }))
        }
    }
}

async fn actualizar_dispositivo(
    pool: web::Data<sqlx::PgPool>,
    id: web::Path<i32>,
    datos: web::Json<DispositivoRequest>,
    usuario: auth::AuthenticatedUser,
) -> impl Responder {
    if let Err(resp) = usuario.exigir_admin() {
    return resp;
    }if let Err(resp) = usuario.exigir_admin() {
    return resp;
    }
    let resultado =
        db::actualizar_dispositivo(&pool, id.into_inner(), &datos.nombre, &datos.tipo, &datos.ip)
            .await;

    match resultado {
        Ok(Some(d)) => HttpResponse::Ok().json(d),
        Ok(None) => {
            HttpResponse::NotFound().json(serde_json::json!({ "error": "Dispositivo no encontrado" }))
        }
        Err(e) => {
            log::warn!("Error actualizando dispositivo: {}", e);
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No se pudo actualizar (¿la IP ya está registrada en otro equipo?)"
            }))
        }
    }
}

async fn eliminar_dispositivo(
    pool: web::Data<sqlx::PgPool>,
    id: web::Path<i32>,
    usuario: auth::AuthenticatedUser,
) -> impl Responder {
    if let Err(resp) = usuario.exigir_admin() {
    return resp;
    }
    match db::eliminar_dispositivo(&pool, id.into_inner()).await {
        Ok(true) => HttpResponse::NoContent().finish(),
        Ok(false) => {
            HttpResponse::NotFound().json(serde_json::json!({ "error": "Dispositivo no encontrado" }))
        }
        Err(e) => {
            log::error!("Error eliminando dispositivo: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Error interno" }))
        }
    }
}

/// Ping real a un dispositivo ya registrado: prueba conectividad, guarda
/// el nuevo estado en `dispositivos` y, si hubo un cambio de estado
/// (ej. online -> offline), genera una alerta automáticamente. Toda esta
/// lógica vive en el backend a propósito: el frontend nunca decide si
/// algo es una alerta, solo la muestra.
async fn ping_dispositivo(
    pool: web::Data<sqlx::PgPool>,
    id: web::Path<i32>,
    _usuario: auth::AuthenticatedUser,
) -> impl Responder {
    let id = id.into_inner();

    let dispositivo_previo = match db::obtener_dispositivo(&pool, id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "error": "Dispositivo no encontrado" }))
        }
        Err(e) => {
            log::error!("Error consultando dispositivo: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Error interno" }));
        }
    };

    let resultado = match ping::probar_conexion(&dispositivo_previo.ip).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("Error ejecutando ping: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Error interno ejecutando ping" }));
        }
    };

    let nuevo_estado = if resultado.en_linea { "online" } else { "offline" };

    // Alerta automática solo si hubo un cambio real de estado -- así no
    // se llena el panel de alertas repitiendo "sigue en línea" cada vez
    // que alguien da clic en "Probar conexión".
    if dispositivo_previo.estado != nuevo_estado {
        let (severidad, mensaje) = if nuevo_estado == "offline" {
            (
                "critica",
                format!(
                    "{} dejó de responder ({})",
                    dispositivo_previo.nombre, dispositivo_previo.ip
                ),
            )
        } else {
            (
                "info",
                format!(
                    "{} volvió a responder ({})",
                    dispositivo_previo.nombre, dispositivo_previo.ip
                ),
            )
        };
        alerts::registrar_alerta(&pool, "ping", severidad, &mensaje, Some(&dispositivo_previo.ip)).await;
    }

    match db::actualizar_estado_dispositivo(&pool, id, nuevo_estado).await {
        Ok(Some(d)) => HttpResponse::Ok().json(serde_json::json!({
            "dispositivo": d,
            "latencia_ms": resultado.latencia_ms,
        })),
        Ok(None) => {
            HttpResponse::NotFound().json(serde_json::json!({ "error": "Dispositivo no encontrado" }))
        }
        Err(e) => {
            log::error!("Error actualizando estado del dispositivo: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Error interno" }))
        }
    }
}

// =====================================================================
// Alertas
// =====================================================================

async fn listar_alertas(
    pool: web::Data<sqlx::PgPool>,
    _usuario: auth::AuthenticatedUser,
) -> impl Responder {
    match db::listar_alertas(&pool, 100).await {
        Ok(lista) => HttpResponse::Ok().json(lista),
        Err(e) => {
            log::error!("Error listando alertas: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Error interno" }))
        }
    }
}

#[derive(Deserialize)]
struct EliminarMasivoRequest {
    ids: Vec<i32>,
}

async fn eliminar_dispositivos_masivo(
    pool: web::Data<sqlx::PgPool>,
    datos: web::Json<EliminarMasivoRequest>,
    usuario: auth::AuthenticatedUser,
) -> impl Responder {
    if let Err(resp) = usuario.exigir_admin() {
    return resp;
    }
    match db::eliminar_dispositivos_masivo(&pool, &datos.ids).await {
        Ok(eliminados) => HttpResponse::Ok().json(serde_json::json!({
            "mensaje": format!("Se eliminaron {} dispositivos correctamente", eliminados),
            "eliminados": eliminados
        })),
        Err(e) => {
            log::error!("Error al eliminar dispositivos masivamente: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Error interno" }))
        }
    }
}

async fn limpiar_dispositivos_inactivos(
    pool: web::Data<sqlx::PgPool>,
    usuario: auth::AuthenticatedUser,
) -> impl Responder {
    if let Err(resp) = usuario.exigir_admin() {
    return resp;
    }
    match db::eliminar_dispositivos_offline(&pool).await {
        Ok(eliminados) => HttpResponse::Ok().json(serde_json::json!({
            "mensaje": format!("Se eliminaron {} dispositivos inactivos/offline", eliminados),
            "eliminados": eliminados
        })),
        Err(e) => {
            log::error!("Error al limpiar dispositivos inactivos: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Error interno" }))
        }
    }
}

async fn grafica_netflow(
    pool: web::Data<sqlx::PgPool>,
    _usuario: auth::AuthenticatedUser,
) -> impl Responder {
    match db::obtener_estadisticas_netflow(&pool).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(e) => {
            log::error!("Error al obtener estadísticas NetFlow: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Error interno" }))
        }
    }
}
