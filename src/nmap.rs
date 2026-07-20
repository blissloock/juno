//! Módulo de escaneo de red con Nmap
//!
//! TODO(equipo): lanzar Nmap como subproceso (crate `tokio::process`, ya
//! está habilitado en Cargo.toml con la feature "process"), pedir salida en
//! XML (`-oX -`) y parsearla con `quick-xml` (ya está en las dependencias).
//!
//! Nota importante de infraestructura: si van a usar escaneos que requieren
//! sockets raw (por ejemplo `-sS`, `-O`), el contenedor del backend necesita
//! las capabilities NET_RAW y NET_ADMIN. Ya dejamos comentado el bloque
//! correspondiente en docker-compose.yml.

use sqlx::PgPool;

/// Placeholder: aquí irá la ejecución periódica o bajo demanda de Nmap.
#[allow(dead_code)]
pub async fn iniciar_escaner_nmap(_pool: PgPool) -> std::io::Result<()> {
    log::info!("Escáner Nmap: pendiente de implementación.");
    Ok(())
}
