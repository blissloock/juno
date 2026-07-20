//! Módulo de alertas por correo (Gmail)
//!
//! TODO(equipo): usar `lettre` (ya está en Cargo.toml) junto con las
//! variables de entorno GMAIL_USER / GMAIL_PASS (ya inyectadas por
//! docker-compose.yml) para enviar correos cuando, por ejemplo, una métrica
//! SNMP supere un umbral o Nmap detecte un puerto/host inesperado.

/// Placeholder para el envío de alertas por correo.
#[allow(dead_code)]
pub async fn enviar_alerta(asunto: &str, cuerpo: &str) -> Result<(), String> {
    log::warn!(
        "Alerta pendiente de implementación -> asunto: '{}', cuerpo: '{}'",
        asunto,
        cuerpo
    );
    Ok(())
}
