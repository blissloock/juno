use crate::db;
use netflow_parser::NetflowParser;
use sqlx::PgPool;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Inicia la sonda NetFlow: escucha paquetes UDP entrantes, los parsea
/// (v5, v9 e IPFIX) y persiste cada flujo como un documento JSON en la
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
    // del loop y conserva su estado entre paquetes. v5 no usa plantillas
    // (formato fijo), así que se parsea aparte con `parsear_netflow_v5` y
    // no necesita estado.
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

        // v5 se parsea a mano (ver parsear_netflow_v5 más abajo). No usa
        // persistir_paquetes porque aquí sí controlamos el struct y
        // podemos serializarlo directo a JSON estructurado, en vez de
        // guardar el texto de Debug como se hace con v9/IPFIX (ver la nota
        // de persistir_paquetes).
        if let Some((count, flujos)) = parsear_netflow_v5(datos_utiles) {
            log::info!(
                "Recibido paquete NetFlow v5 de {} ({} bytes, {} flujo(s))",
                origen, tamaño, count
            );
            log::debug!("Detalle del flujo v5: {:?}", flujos);
            let datos_json = serde_json::json!({
                "protocolo": "netflow_v5",
                "cantidad_flujos": count,
                "flujos": flujos,
            });
            if let Err(e) =
                db::insertar_evento(&pool, "netflow", Some(&origen_ip), &datos_json).await
            {
                log::error!(
                    "No se pudo guardar el evento NetFlow v5 en la base de datos: {}",
                    e
                );
            }
            continue;
        }

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
            "Paquete UDP recibido de {} no coincide con NetFlow v5, v9 ni IPFIX.",
            origen
        );
    }
}

/// Parseo manual del formato NetFlow v5 (formato clásico, sin plantillas).
///
/// Por qué esto es manual y no usa la crate `netflow_parser` como v9/IPFIX:
/// la versión 0.5.9 que tenemos fijada en Cargo.toml solo expone parsers
/// para v9 e IPFIX (`parser.v9_parser` / `parser.ipfix_parser` como
/// campos) -- no tiene un `v5_parser` (confirmado por el propio
/// compilador: "no field `v5_parser` on type `NetflowParser`"). Subir de
/// versión de esa crate es arriesgado porque las versiones más nuevas
/// cambiaron toda la API a un solo método `parse_bytes()` unificado, lo
/// que rompería el código de v9/IPFIX que YA funciona. En cambio, v5 es
/// un formato de bytes fijo y documentado desde hace décadas (Cisco nunca
/// lo ha cambiado), así que parsearlo a mano es más corto, no depende de
/// ninguna crate externa, y no se rompe con un `cargo update` futuro.
///
/// Formato del paquete:
///   - Header: 24 bytes fijos (los primeros 2 bytes son la versión; si no
///     es 5, se regresa None para que el llamador pruebe otro parser).
///   - Luego, `count` registros de flujo de 48 bytes cada uno (`count`
///     viene en los bytes 2-3 del header).
fn parsear_netflow_v5(datos: &[u8]) -> Option<(u16, Vec<FlujoV5>)> {
    const TAM_HEADER: usize = 24;
    const TAM_REGISTRO: usize = 48;

    if datos.len() < TAM_HEADER {
        return None;
    }

    let version = u16::from_be_bytes([datos[0], datos[1]]);
    if version != 5 {
        return None; // no es v5: que lo intenten los otros parsers
    }

    let count = u16::from_be_bytes([datos[2], datos[3]]) as usize;

    // Si el paquete dice traer más registros de los que realmente caben
    // en los bytes recibidos, algo viene truncado/corrupto -- mejor
    // rechazarlo aquí que leer fuera de rango más abajo.
    if datos.len() < TAM_HEADER + count * TAM_REGISTRO {
        return None;
    }

    let mut flujos = Vec::with_capacity(count);
    for i in 0..count {
        let inicio = TAM_HEADER + i * TAM_REGISTRO;
        let r = &datos[inicio..inicio + TAM_REGISTRO];

        flujos.push(FlujoV5 {
            ip_origen: std::net::Ipv4Addr::new(r[0], r[1], r[2], r[3]),
            ip_destino: std::net::Ipv4Addr::new(r[4], r[5], r[6], r[7]),
            ip_siguiente_salto: std::net::Ipv4Addr::new(r[8], r[9], r[10], r[11]),
            paquetes: u32::from_be_bytes([r[16], r[17], r[18], r[19]]),
            bytes: u32::from_be_bytes([r[20], r[21], r[22], r[23]]),
            puerto_origen: u16::from_be_bytes([r[32], r[33]]),
            puerto_destino: u16::from_be_bytes([r[34], r[35]]),
            tcp_flags: r[37],
            protocolo: r[38],
            tos: r[39],
        });
    }

    Some((count as u16, flujos))
}

/// Un registro de flujo NetFlow v5 ya decodificado. A diferencia de v9/
/// IPFIX (que vienen de una crate externa sin `Serialize`, ver
/// `persistir_paquetes`), este struct es nuestro y sí implementa
/// `Serialize` directo -- así que el documento que se guarda en `eventos`
/// para v5 queda con campos estructurados de verdad, consultables con
/// `datos->'flujos'->0->>'ip_origen'` en vez de solo texto plano.
#[derive(Debug, serde::Serialize)]
struct FlujoV5 {
    ip_origen: std::net::Ipv4Addr,
    ip_destino: std::net::Ipv4Addr,
    ip_siguiente_salto: std::net::Ipv4Addr,
    puerto_origen: u16,
    puerto_destino: u16,
    paquetes: u32,
    bytes: u32,
    protocolo: u8,
    tos: u8,
    tcp_flags: u8,
}

/// Guarda los paquetes ya parseados (v9/IPFIX) como un documento en la
/// colección `eventos` (tipo = "netflow").
///
/// Nota técnica: el tipo que regresa `netflow_parser` (`ParsedNetflow`) NO
/// implementa `serde::Serialize`, solo `Debug` -- es una limitación del
/// crate externo, no algo que podamos arreglar agregando un `#[derive]`
/// porque no es código nuestro. Por eso guardamos su representación
/// `Debug` como texto dentro del campo `paquete` en vez de intentar
/// convertirlo a un objeto JSON anidado. Sigue siendo un documento JSONB
/// válido y consultable (pueden buscar dentro de ese texto con `LIKE` o
/// `datos->>'paquete' LIKE '%...%'`), solo que el detalle del paquete
/// queda como string en vez de campos estructurados. (v5 no tiene este
/// problema: ver `parsear_netflow_v5` y `FlujoV5`, arriba.)
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
