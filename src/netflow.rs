use tokio::net::UdpSocket;
use netflow_parser::NetflowParser;
use sqlx::PgPool;
use std::io;
use std::net::SocketAddr;

/// Inicia la sonda NetFlow: escucha paquetes UDP entrantes, los parsea
/// (v9 e IPFIX) y deja el punto listo para persistirlos en la base de datos.
///
/// Recibe el `pool` de conexiones para que, cuando se implemente la
/// persistencia en `db.rs`, cada flujo detectado pueda guardarse
/// directamente desde aquí.
pub async fn iniciar_sonda_netflow(_pool: PgPool) -> io::Result<()> {
    let direccion = "0.0.0.0:2055";
    let socket = UdpSocket::bind(direccion).await?;
    log::info!("Sonda NetFlow activa y escuchando en UDP://{}", direccion);

    let mut buffer = [0u8; 65535];

    // BUG CORREGIDO:
    // Antes, `NetflowParser::default()` se creaba DENTRO del `loop`, es decir,
    // en cada paquete recibido. Este parser mantiene estado interno (por
    // ejemplo, plantillas de NetFlow v9/IPFIX que llegan por separado de los
    // datos), así que recrearlo en cada iteración lo dejaba "amnésico": nunca
    // llegaba a acumular las plantillas necesarias para decodificar los
    // paquetes de datos correctamente. Ahora se crea una sola vez, antes del
    // loop, y conserva su estado entre paquetes.
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

        if let Ok(paquetes) = parser.v9_parser.parse(datos_utiles) {
            log::info!("Recibido paquete NetFlow v9 de {} ({} bytes)", origen, tamaño);
            log::debug!("Detalle del flujo v9: {:?}", paquetes);
            // TODO(equipo): persistir `paquetes` en la base de datos usando `_pool`
            // (ver las funciones de ejemplo en db.rs).
            continue;
        }

        if let Ok(paquetes) = parser.ipfix_parser.parse(datos_utiles) {
            log::info!("Recibido paquete IPFIX de {} ({} bytes)", origen, tamaño);
            log::debug!("Detalle del flujo IPFIX: {:?}", paquetes);
            // TODO(equipo): persistir `paquetes` en la base de datos usando `_pool`.
            continue;
        }

        log::warn!(
            "Paquete UDP recibido de {} no coincide con NetFlow v9 ni IPFIX.",
            origen
        );
    }
}
