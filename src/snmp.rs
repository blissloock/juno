//! Módulo de monitoreo SNMP
//!
//! TODO(equipo): implementar el polling periódico (get/walk) contra el
//! router y el HP Z620 para obtener CPU, RAM, estado de interfaces, etc.,
//! y persistirlo con las funciones de `db.rs`.
//!
//! Sugerencia de flujo:
//! 1. Cargar de un config/env la lista de hosts + community string SNMP.
//! 2. cada N segundos, hacer un GET/WALK por host (crate `snmp`).
//! 3. Insertar el resultado en TimescaleDB vía `pool`.

use sqlx::PgPool;

/// Placeholder: aquí irá el loop periódico de polling SNMP.
/// Se deja `_pool` con guion bajo para que el proyecto compile sin
/// warnings mientras no tenga cuerpo real.
#[allow(dead_code)]
pub async fn iniciar_monitor_snmp(_pool: PgPool) -> std::io::Result<()> {
    log::info!("Monitor SNMP: pendiente de implementación.");
    Ok(())
}
