//! Módulo de detección de anomalías en el tráfico de red (IDS ligero).
//!
//! Reutiliza la entropía de Shannon sobre el tráfico NetFlow que ya se
//! calcula en `db::obtener_estadisticas_netflow` (columna `entropia_red`,
//! visible en el dashboard bajo "Métricas & NetFlow"). Una entropía alta
//! indica que el tráfico está muy disperso entre muchos orígenes
//! distintos -- un patrón típico de un escaneo de red o de un host
//! comprometido "hablando" con muchos destinos a la vez. Una entropía muy
//! baja (todo el tráfico concentrado en pocos orígenes) es normal en la
//! mayoría de redes pequeñas.
//!
//! Esto NO es un IDS de firmas como Snort/Suricata -- es una heurística
//! simple basada en un solo umbral, pensada para el alcance de este
//! proyecto. Se documenta así a propósito para la defensa: es honesto
//! sobre qué tan sofisticada es la detección.

use crate::alerts;
use sqlx::PgPool;
use std::env;
use std::time::Duration;

pub async fn iniciar_monitor_entropia(pool: PgPool) -> std::io::Result<()> {
    let umbral: f64 = env::var("NETFLOW_ENTROPIA_UMBRAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3.5);

    let intervalo: u64 = env::var("NETFLOW_ENTROPIA_INTERVALO_SEGUNDOS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    log::info!(
        "Monitor de entropía NetFlow activo: umbral={:.2} bits, cada {}s",
        umbral,
        intervalo
    );

    // Solo generamos una alerta nueva cuando CRUZAMOS el umbral (de
    // normal a anómalo), no en cada intervalo mientras seguimos arriba
    // del umbral -- mismo patrón que ya usan en ping_dispositivo para no
    // inundar el panel de alertas repitiendo lo mismo.
    let mut en_estado_anomalo = false;

    loop {
        tokio::time::sleep(Duration::from_secs(intervalo)).await;

        let stats = match crate::db::obtener_estadisticas_netflow(&pool).await {
            Ok(s) => s,
            Err(e) => {
                log::error!("No se pudo calcular la entropía NetFlow: {}", e);
                continue;
            }
        };

        // Sin suficiente tráfico todavía, no tiene sentido evaluar.
        if stats.total_flujos < 10 {
            continue;
        }

        let es_anomalo = stats.entropia_red >= umbral;

        if es_anomalo && !en_estado_anomalo {
            let top_origen = stats
                .top_hosts
                .first()
                .map(|h| h.origen.clone())
                .unwrap_or_else(|| "desconocido".to_string());

            let mensaje = format!(
                "Entropía de tráfico NetFlow elevada: {:.2} bits (umbral {:.2}). \
                 Posible escaneo de red o tráfico disperso inusual. Origen más activo: {}.",
                stats.entropia_red, umbral, top_origen
            );

            alerts::registrar_alerta(&pool, "netflow_entropia", "advertencia", &mensaje, None).await;
            log::warn!("{}", mensaje);
        }

        en_estado_anomalo = es_anomalo;
    }
}