//! Módulo de monitoreo SNMP.
//!
//! Hace polling periódico contra los hosts definidos en la variable de
//! entorno `SNMP_HOSTS` (formato "host:community,host2:community2") y
//! guarda cada lectura como un documento en la colección `eventos`
//! (tipo = "snmp"), igual que hace `netflow.rs`. Además, si logra parsear
//! valores numéricos útiles (carga de CPU, memoria), actualiza
//! `dispositivos.cpu_pct`/`ram_pct` -- eso es lo que el dashboard lee
//! para pintar los gauges, así que sin este paso el frontend siempre
//! mostraría "N/D" aunque el polling SNMP estuviera funcionando bien.
//!
//! Nota técnica importante: el crate `snmp` es SÍNCRONO (usa
//! `std::net::UdpSocket` con timeout por debajo, no tokio). Si lo
//! llamáramos directamente desde una tarea async, bloquearíamos el
//! runtime de tokio mientras espera la respuesta del dispositivo. Por eso
//! la consulta real corre dentro de `tokio::task::spawn_blocking`.
//!
//! Nota sobre el formato guardado en `eventos`: al igual que con NetFlow,
//! el PDU que regresa el crate `snmp` no implementa `serde::Serialize`
//! (solo `Debug`), así que guardamos su representación `Debug` completa
//! dentro del documento JSON en vez de intentar reconstruirlo campo por
//! campo. Es información completa y consultable igual, solo que como
//! texto. Para las métricas que sí necesitamos como número (CPU/RAM),
//! extraemos el valor tipado del varbind por separado (ver
//! `valor_a_f64`), sin depender de parsear ese texto de Debug.

use crate::db;
use snmp::{SyncSession, Value};
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
    ("laLoad_1min", &[1, 3, 6, 1, 4, 1, 2021, 10, 1, 3, 1]),   // UCD-SNMP (Linux)
    ("memTotalReal", &[1, 3, 6, 1, 4, 1, 2021, 4, 5, 0]),      // UCD-SNMP (Linux)
    ("memAvailReal", &[1, 3, 6, 1, 4, 1, 2021, 4, 6, 0]),      // UCD-SNMP (Linux)
    ("ciscoCpu5min", &[1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 7, 1]),  // CISCO-PROCESS-MIB
    ("ciscoMemUsado", &[1, 3, 6, 1, 4, 1, 9, 9, 48, 1, 1, 1, 5, 1]),     // CISCO-MEMORY-POOL-MIB
    ("ciscoMemLibre", &[1, 3, 6, 1, 4, 1, 9, 9, 48, 1, 1, 1, 6, 1]),     // CISCO-MEMORY-POOL-MIB
];

#[derive(Clone)]
struct HostSnmp {
    host: String,
    community: String,
}

/// Resultado de convertir los varbinds crudos a algo que sí podemos
/// guardar como columna numérica en `dispositivos`.
#[derive(Debug, Default)]
struct MetricasParsed {
    cpu_pct: Option<f32>,
    ram_pct: Option<f32>,
}

/// Convierte un `Value` de SNMP a `f64` sin importar el tipo ASN.1 exacto
/// con el que haya respondido el agente (distintos agentes devuelven
/// enteros como Integer, Counter32, Unsigned32 o incluso como texto).
fn valor_a_f64(valor: &Value) -> Option<f64> {
    match valor {
        Value::Integer(i) => Some(*i as f64),
        Value::Counter32(u) => Some(*u as f64),
        Value::Unsigned32(u) => Some(*u as f64),
        Value::Timeticks(u) => Some(*u as f64),
        Value::Counter64(u) => Some(*u as f64),
        Value::OctetString(bytes) => std::str::from_utf8(bytes).ok()?.trim().parse::<f64>().ok(),
        _ => None,
    }
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

    let (datos, metricas) =
        tokio::task::spawn_blocking(move || consultar_snmp_bloqueante(&host, &community))
            .await
            .map_err(|e| format!("la tarea SNMP se canceló: {}", e))??;

    db::insertar_evento(pool, "snmp", Some(&cfg.host), &datos)
        .await
        .map_err(|e| format!("error guardando en base de datos: {}", e))?;

    // Solo intentamos actualizar el catálogo si logramos parsear algo
    // numérico. Si el dispositivo todavía no está registrado en
    // `dispositivos` (UPDATE sin filas afectadas), no es un error --
    // simplemente no hay nada que actualizar todavía.
    if metricas.cpu_pct.is_some() || metricas.ram_pct.is_some() {
        if let Err(e) =
            db::actualizar_metricas_dispositivo(pool, &cfg.host, metricas.cpu_pct, metricas.ram_pct)
                .await
        {
            log::warn!(
                "SNMP respondió en {} pero no se pudo guardar la métrica en 'dispositivos': {}",
                cfg.host, e
            );
        }
    }

    Ok(())
}

/// Consulta síncrona real vía SNMP GET. Se ejecuta dentro de
/// `spawn_blocking` (ver `consultar_host`). Regresa tanto el documento
/// JSON crudo (para `eventos`) como las métricas ya parseadas a número
/// (para `dispositivos`).
fn consultar_snmp_bloqueante(
    host: &str,
    community: &str,
) -> Result<(serde_json::Value, MetricasParsed), String> {
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
    let mut numericos: std::collections::HashMap<&str, f64> = std::collections::HashMap::new();
    let mut algun_exito = false;

    for (nombre, oid) in OIDS_A_CONSULTAR {
        match sesion.get(oid) {
            Ok(mut pdu) => {
                algun_exito = true;
                // Guardamos el Debug completo del PDU, igual que antes
                // (ver nota técnica al inicio del archivo).
                valores.insert((*nombre).to_string(), serde_json::json!(format!("{:?}", pdu)));

                // Además, intentamos extraer el valor tipado del primer
                // varbind de la respuesta para poder convertirlo a número.
                if let Some((_oid_resp, valor)) = pdu.varbinds.next() {
                    if let Some(num) = valor_a_f64(&valor) {
                        numericos.insert(*nombre, num);
                    }
                }
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

    // cpmCPUTotal5minRev (Cisco) ya viene como porcentaje real 0-100 --
    // a diferencia del "load average" de Linux, no necesita ninguna
    // conversión. El índice ".1" al final asume un solo CPU lógico, que
    // es el caso normal en un 1841.
    let cpu_pct = numericos
        .get("ciscoCpu5min")
        .map(|c| (*c as f32).clamp(0.0, 100.0))
        .or_else(|| {
            numericos
                .get("laLoad_1min")
                .map(|carga| (carga * 100.0).clamp(0.0, 100.0) as f32)
        });

    let ram_pct = match (numericos.get("ciscoMemUsado"), numericos.get("ciscoMemLibre")) {
        (Some(usado), Some(libre)) if (usado + libre) > 0.0 => {
            Some(((usado / (usado + libre)) * 100.0).clamp(0.0, 100.0) as f32)
        }
        _ => match (numericos.get("memTotalReal"), numericos.get("memAvailReal")) {
            (Some(total), Some(disponible)) if *total > 0.0 => {
                Some((((total - disponible) / total) * 100.0).clamp(0.0, 100.0) as f32)
            }
            _ => None,
        },
    };

    Ok((
        serde_json::json!({
            "host": host,
            "community_usada": community,
            "valores": valores,
        }),
        MetricasParsed { cpu_pct, ram_pct },
    ))
}
