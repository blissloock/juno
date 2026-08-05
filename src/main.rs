use ProyectoIntegrador::{auth, db, netflow};

use actix_cors::Cors;
use actix_web::{http, middleware, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    log::info!("Iniciando Backend del Proyecto Integrador...");

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

    // TODO(equipo): mismo patrón para snmp::iniciar_monitor_snmp y el
    // escáner de nmap cuando estén implementados. Ambos ya pueden usar
    // db::insertar_evento(pool, "snmp" | "nmap", origen, &datos_json) para
    // persistir, igual que hace netflow.rs.

    let puerto: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    // El origen permitido para CORS sale de una variable de entorno: en
    // desarrollo puede ser http://localhost:80, en producción el dominio
    // real del dashboard. IMPORTANTE: nunca usar Cors::permissive() en
    // producción, eso deja la API abierta a que cualquier sitio web la
    // consuma con las credenciales del usuario que la esté visitando.
    let frontend_origin =
        std::env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "http://localhost:80".to_string());

    log::info!("Arrancando servidor web en http://0.0.0.0:{}", puerto);
    log::info!("CORS restringido a origen: {}", frontend_origin);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&frontend_origin)
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::CONTENT_TYPE])
            .max_age(3600);

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
        // TODO(equipo): agreguen aquí el resto de rutas del dashboard.
        // Para proteger cualquiera de ellas con login, basta con agregar
        // `usuario: auth::AuthenticatedUser` como parámetro del handler,
        // igual que en `perfil`.
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
        Ok(token) => HttpResponse::Ok().json(serde_json::json!({ "token": token })),
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
