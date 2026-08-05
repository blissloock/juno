use crate::db;
use netflow_parser::NetflowParser;
use sqlx::PgPool;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Inicia la sonda NetFlow: escucha paquetes UDP entrantes, los parsea
/// (v9 e IPFIX) y persiste cada flujo como un documento JSON en la
/// colección `eventos` (ver migrations/0002_documentos_json.sql y
/// db::insertar_evento). No hace falta que todos los paquetes tengan
/// exactamente los mismos campos: al ser JSONB, cada documento puede traer
/// justo la información que trajo ese paquete.
pub async fn iniciar_sonda_netflow(pool: PgPool) -> io::Result<()> {
    let direccion = "0.0.0.0:2055";
    let socket = UdpSocket::bind(direccion).await?;
    log::info!("Sonda NetFlow activa y escuchando en UDP://{}", direccion);

    let mut buffer = [0u8; 65535];

    // El parser mantiene estado interno (plantillas de NetFlow v9/IPFIX que
    // llegan por separado de los datos), así que se crea una sola vez antes
    // del loop y conserva su estado entre paquetes.
    let mut parser = NetflowParser::default();

    loop {
        let (tamaño, origen): (usize, SocketAddr) = match socket.recv_from(&mut buffer).await {
            Ok(resultado) => resultado,
            Err(e) => {
                log::error!("Error al recibir paquete UDP: {}", e);
                continue;
            }
        };

        let datos_utiles = &buffer[..tamaño];
        let origen_ip = origen.ip().to_string();

        if let Ok(paquetes) = parser.v9_parser.parse(datos_utiles) {
            log::info!("Recibido paquete NetFlow v9 de {} ({} bytes)", origen, tamaño);
            log::debug!("Detalle del flujo v9: {:?}", paquetes);
            persistir_paquetes(&pool, "netflow_v9", &origen_ip, &paquetes).await;
            continue;
        }

        if let Ok(paquetes) = parser.ipfix_parser.parse(datos_utiles) {
            log::info!("Recibido paquete IPFIX de {} ({} bytes)", origen, tamaño);
            log::debug!("Detalle del flujo IPFIX: {:?}", paquetes);
            persistir_paquetes(&pool, "ipfix", &origen_ip, &paquetes).await;
            continue;
        }

        log::warn!(
            "Paquete UDP recibido de {} no coincide con NetFlow v9 ni IPFIX.",
            origen
        );
    }
}

/// Guarda los paquetes ya parseados como un documento en la colección
/// `eventos` (tipo = "netflow").
///
/// Nota técnica: el tipo que regresa `netflow_parser` (`ParsedNetflow`) NO
/// implementa `serde::Serialize`, solo `Debug` -- es una limitación del
/// crate externo, no algo que podamos arreglar agregando un `#[derive]`
/// porque no es código nuestro. Por eso guardamos su representación
/// `Debug` como texto dentro del campo `paquete` en vez de intentar
/// convertirlo a un objeto JSON anidado. Sigue siendo un documento JSONB
/// válido y consultable (pueden buscar dentro de ese texto con `LIKE` o
/// `datos->>'paquete' LIKE '%...%'`), solo que el detalle del paquete
/// queda como string en vez de campos estructurados.
async fn persistir_paquetes<T: std::fmt::Debug>(
    pool: &PgPool,
    subtipo: &str,
    origen_ip: &str,
    paquetes: &T,
) {
    let datos = serde_json::json!({
        "protocolo": subtipo,
        "paquete": format!("{:?}", paquetes),
    });

    if let Err(e) = db::insertar_evento(pool, "netflow", Some(origen_ip), &datos).await {
        log::error!("No se pudo guardar el evento NetFlow en la base de datos: {}", e);
    }
}