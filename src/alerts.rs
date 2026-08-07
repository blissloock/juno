//! Módulo de alertas: registro en base de datos + notificación por correo
//! (Gmail) para las alertas críticas.
//!
//! Diseño: TODAS las alertas se guardan en la tabla `alertas` (para que
//! siempre queden visibles en el panel del frontend, sin importar si el
//! correo falla o no está configurado). Solo las de severidad "critica"
//! además disparan un correo -- así no se satura el buzón con cada
//! advertencia de entropía o evento informativo; el correo se reserva
//! para lo que de verdad necesita atención inmediata (ej. un dispositivo
//! que dejó de responder).
//!
//! Requiere las variables de entorno GMAIL_USER / GMAIL_PASS (ya
//! inyectadas por docker-compose.yml). GMAIL_PASS debe ser una
//! "contraseña de aplicación" de Google, no la contraseña normal de la
//! cuenta (Gmail no permite SMTP con la contraseña normal si tienen
//! verificación en dos pasos activada, que es justo lo recomendado).
//!
//! Si el correo falla (credenciales mal puestas, sin internet, etc.), NO
//! se propaga como error hacia quien llamó -- la alerta ya quedó guardada
//! en la base de datos y visible en el dashboard, que es lo importante;
//! el correo es un "extra", no debe tumbar la petición HTTP que la
//! disparó.

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use sqlx::PgPool;
use std::env;

use crate::db;

/// Registra una alerta: siempre en la base de datos y, si la severidad es
/// "critica", también por correo. Los handlers/monitores deben usar esta
/// función en vez de llamar a `db::crear_alerta` directamente, para que
/// la política de "solo lo crítico se manda por correo" viva en un solo
/// lugar.
pub async fn registrar_alerta(
    pool: &PgPool,
    tipo: &str,
    severidad: &str,
    mensaje: &str,
    origen: Option<&str>,
) {
    if let Err(e) = db::crear_alerta(pool, tipo, severidad, mensaje, origen).await {
        log::error!("No se pudo guardar la alerta en la base de datos: {}", e);
    }

    if severidad == "critica" {
        let asunto = format!("[Juno] Alerta crítica: {}", tipo);
        let cuerpo = match origen {
            Some(o) => format!("{}\n\nOrigen: {}", mensaje, o),
            None => mensaje.to_string(),
        };
        if let Err(e) = enviar_alerta(&asunto, &cuerpo).await {
            log::error!("No se pudo enviar el correo de alerta: {}", e);
        }
    }
}

/// Envía un correo de alerta usando SMTP de Gmail (TLS implícito, puerto
/// 465 -- el método recomendado por lettre, no requiere STARTTLS aparte).
pub async fn enviar_alerta(asunto: &str, cuerpo: &str) -> Result<(), String> {
    let usuario = env::var("GMAIL_USER").map_err(|_| "GMAIL_USER no está definida".to_string())?;
    let password = env::var("GMAIL_PASS").map_err(|_| "GMAIL_PASS no está definida".to_string())?;
    // Por defecto se manda a la misma cuenta configurada (uso típico en
    // un homelab: "avísame a mí mismo"). Se puede sobreescribir con
    // ALERT_EMAIL_TO si quieren mandarlo a otra bandeja.
    let destino = env::var("ALERT_EMAIL_TO").unwrap_or_else(|_| usuario.clone());

    let remitente: Mailbox = usuario
        .parse()
        .map_err(|e| format!("GMAIL_USER no es un correo válido: {}", e))?;
    let receptor: Mailbox = destino
        .parse()
        .map_err(|e| format!("ALERT_EMAIL_TO no es un correo válido: {}", e))?;

    let correo = Message::builder()
        .from(remitente)
        .to(receptor)
        .subject(asunto)
        .body(cuerpo.to_string())
        .map_err(|e| format!("No se pudo construir el correo: {}", e))?;

    let credenciales = Credentials::new(usuario, password);

    let transportador = AsyncSmtpTransport::<Tokio1Executor>::relay("smtp.gmail.com")
        .map_err(|e| format!("No se pudo configurar el relay SMTP: {}", e))?
        .credentials(credenciales)
        .build();

    transportador
        .send(correo)
        .await
        .map_err(|e| format!("Error enviando el correo: {}", e))?;

    log::info!("Correo de alerta enviado: '{}'", asunto);
    Ok(())
}