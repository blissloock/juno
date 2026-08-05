//! Módulo de monitoreo SNMP.
//!
//! Hace polling periódico contra los hosts definidos en la variable de
//! entorno `SNMP_HOSTS` (formato "host:community,host2:community2") y
//! guarda cada lectura como un documento en la colección `eventos`
//! (tipo = "snmp"), igual que hace `netflow.rs`.
//!
//! Nota técnica importante: el crate `snmp` es SÍNCRONO (usa
//! `std::net::UdpSocket` con timeout por debajo, no tokio). Si lo
//! llamáramos directamente desde una tarea async, bloquearíamos el
//! runtime de tokio mientras espera la respuesta del dispositivo. Por eso
//! la consulta real corre dentro de `tokio::task::spawn_blocking`.
//!
//! Nota sobre el formato guardado: al igual que con NetFlow, el PDU que
//! regresa el crate `snmp` no implementa `serde::Serialize` (solo
//! `Debug`), así que guardamos su representación `Debug` completa dentro
//! del documento JSON en vez de intentar reconstruirlo campo por campo.
//! Es información completa y consultable igual, solo que como texto.

use crate::db;
use snmp::SyncSession;
use sqlx::PgPool;
use std::env;
use std::net::ToSocketAddrs;
use std::time::Duration;

/// OIDs estándar (MIB-2) + UCD-SNMP-MIB (típico en agentes net-snmp de
/// Linux, como el HP Z620), cada uno con un nombre legible.
///
/// Nota técnica: en esta versión del crate `snmp`, `SyncSession::get`
/// recibe UN SOLO OID por llamada (`&[u32]`), no una lista de varios OIDs
/// a la vez. Por eso se consulta cada uno por separado en un loop (ver
/// `consultar_snmp_bloqueante`) en vez de mandarlos todos juntos en un
/// solo GET-PDU. Efecto secundario positivo: si un dispositivo (por
/// ejemplo un Cisco que no expone los OIDs de UCD-SNMP) falla en uno
/// específico, los demás igual quedan guardados en vez de perderse todos.
const OIDS_A_CONSULTAR: &[(&str, &[u32])] = &[
    ("sysDescr", &[1, 3, 6, 1, 2, 1, 1, 1, 0]),
    ("sysUpTime", &[1, 3, 6, 1, 2, 1, 1, 3, 0]),
    ("laLoad_1min", &[1, 3, 6, 1, 4, 1, 2021, 10, 1, 3, 1]), // UCD-SNMP: carga CPU 1 min
    ("memTotalReal", &[1, 3, 6, 1, 4, 1, 2021, 4, 5, 0]),
    ("memAvailReal", &[1, 3, 6, 1, 4, 1, 2021, 4, 6, 0]),
];

#[derive(Clone)]
struct HostSnmp {
    host: String,
    community: String,
}

/// Lee `SNMP_HOSTS` del entorno. Formato: "192.168.1.1:public,10.0.0.1:public".
/// Si no está definida, el monitor queda inactivo (no es un error: hay
/// entornos donde todavía no se configuró ningún dispositivo SNMP).
fn cargar_hosts_desde_env() -> Vec<HostSnmp> {
    env::var("SNMP_HOSTS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|entrada| {
            let entrada = entrada.trim();
            if entrada.is_empty() {
                return None;
            }
            let mut partes = entrada.splitn(2, ':');
            let host = partes.next()?.trim().to_string();
            let community = partes.next().unwrap_or("public").trim().to_string();
            Some(HostSnmp { host, community })
        })
        .collect()
}

/// Loop principal: cada `SNMP_INTERVALO_SEGUNDOS` (default 30s) consulta
/// todos los hosts configurados en paralelo.
pub async fn iniciar_monitor_snmp(pool: PgPool) -> std::io::Result<()> {
    let hosts = cargar_hosts_desde_env();

    if hosts.is_empty() {
        log::warn!(
            "Monitor SNMP: no hay hosts configurados en SNMP_HOSTS. \
             El monitor queda inactivo hasta que se configure."
        );
        return Ok(());
    }

    let intervalo: u64 = env::var("SNMP_INTERVALO_SEGUNDOS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    log::info!(
        "Monitor SNMP activo: {} host(s), cada {}s",
        hosts.len(),
        intervalo
    );

    loop {
        for host_cfg in &hosts {
            let pool = pool.clone();
            let host_cfg = host_cfg.clone();
            // Cada host se consulta en su propia tarea: un dispositivo
            // caído/lento (timeout de varios segundos) no debe retrasar
            // la lectura de los demás.
            tokio::spawn(async move {
                if let Err(e) = consultar_host(&pool, &host_cfg).await {
                    log::error!("Error consultando SNMP en {}: {}", host_cfg.host, e);
                }
            });
        }
        tokio::time::sleep(Duration::from_secs(intervalo)).await;
    }
}

async fn consultar_host(pool: &PgPool, cfg: &HostSnmp) -> Result<(), String> {
    let host = cfg.host.clone();
    let community = cfg.community.clone();

    let datos = tokio::task::spawn_blocking(move || consultar_snmp_bloqueante(&host, &community))
        .await
        .map_err(|e| format!("la tarea SNMP se canceló: {}", e))??;

    db::insertar_evento(pool, "snmp", Some(&cfg.host), &datos)
        .await
        .map_err(|e| format!("error guardando en base de datos: {}", e))
}

/// Consulta síncrona real vía SNMP GET. Se ejecuta dentro de
/// `spawn_blocking` (ver `consultar_host`).
fn consultar_snmp_bloqueante(host: &str, community: &str) -> Result<serde_json::Value, String> {
    let direccion = format!("{}:161", host)
        .to_socket_addrs()
        .map_err(|e| format!("dirección inválida '{}': {}", host, e))?
        .next()
        .ok_or_else(|| format!("no se pudo resolver '{}'", host))?;

    let mut sesion = SyncSession::new(
        direccion,
        community.as_bytes(),
        Some(Duration::from_secs(3)),
        0,
    )
    .map_err(|e| format!("no se pudo abrir sesión SNMP: {:?}", e))?;

    let mut valores = serde_json::Map::new();
    let mut algun_exito = false;

    for (nombre, oid) in OIDS_A_CONSULTAR {
        match sesion.get(oid) {
            Ok(pdu) => {
                algun_exito = true;
                // Ver nota técnica al inicio del archivo sobre por qué
                // esto va como texto (Debug) y no como objeto JSON
                // estructurado: el PDU no implementa Serialize.
                valores.insert((*nombre).to_string(), serde_json::json!(format!("{:?}", pdu)));
            }
            Err(e) => {
                log::debug!("OID '{}' no respondió en {}: {:?}", nombre, host, e);
                valores.insert(
                    (*nombre).to_string(),
                    serde_json::json!(format!("sin respuesta: {:?}", e)),
                );
            }
        }
    }

    if !algun_exito {
        return Err(format!(
            "ningún OID respondió en {} (revisa host/community/firewall)",
            host
        ));
    }

    Ok(serde_json::json!({
        "host": host,
        "community_usada": community,
        "valores": valores,
    }))
}