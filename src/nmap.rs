//! Módulo de escaneo de red con Nmap.
//!
//! `escanear_host` ejecuta Nmap como subproceso, pide salida en XML
//! (`-oX -`) y la parsea con `quick-xml` para extraer puertos abiertos y
//! sistema operativo detectado. Pensado para llamarse bajo demanda desde
//! un endpoint HTTP (ver `main.rs`, botón "Escanear Dispositivo (Auto)"
//! del frontend), y opcionalmente también en un loop periódico si se
//! define `NMAP_HOSTS`.
//!
//! Nota de infraestructura: por defecto NO se usa `-O` (detección de SO)
//! ni `-sS` (SYN scan) porque ambos requieren sockets raw, es decir, las
//! capabilities `NET_RAW`/`NET_ADMIN` que están comentadas en
//! `docker-compose.yml`. Con un TCP connect scan normal (lo que hace este
//! módulo) alcanza para detectar puertos abiertos sin privilegios extra.
//! Si más adelante quieren detección de SO, descomenten esas capabilities
//! y agreguen `-O` al comando.
//!
//! Nota técnica sobre el parseo: si el XML trae un campo que el parser no
//! reconoce (por ejemplo, una versión distinta de nmap), no se pierde
//! información: el XML completo se guarda también en `xml_crudo` dentro
//! del documento JSON.

use crate::db;
use quick_xml::events::Event;
use quick_xml::Reader;
use sqlx::PgPool;
use std::env;
use std::time::Duration;
use tokio::process::Command;

/// Ejecuta un escaneo Nmap contra `host`, guarda el resultado como
/// documento en `eventos` (tipo = "nmap") y lo regresa para que el
/// endpoint HTTP se lo pueda mandar de inmediato al frontend.
pub async fn escanear_host(pool: &PgPool, host: &str) -> Result<serde_json::Value, String> {
    log::info!("Iniciando escaneo Nmap contra {}", host);

    let salida = Command::new("nmap")
        .arg("-oX")
        .arg("-") // XML a stdout, sin escribir archivo temporal
        .arg("-T4")
        .arg("--top-ports")
        .arg("100") // escaneo rápido: top 100 puertos, no los 65535
        .arg(host)
        .output()
        .await
        .map_err(|e| format!("no se pudo ejecutar nmap (¿está instalado en el contenedor?): {}", e))?;

    if !salida.status.success() {
        return Err(format!(
            "nmap terminó con error: {}",
            String::from_utf8_lossy(&salida.stderr)
        ));
    }

    let xml = String::from_utf8_lossy(&salida.stdout).to_string();
    let datos = parsear_xml_nmap(&xml, host);

    db::insertar_evento(pool, "nmap", Some(host), &datos)
        .await
        .map_err(|e| format!("error guardando escaneo en base de datos: {}", e))?;

    Ok(datos)
}

/// Extrae puertos abiertos y sistema operativo detectado del XML de nmap.
fn parsear_xml_nmap(xml: &str, host: &str) -> serde_json::Value {
    let mut lector = Reader::from_str(xml);
    lector.trim_text(true);

    let mut puertos = Vec::new();
    let mut so_detectado: Option<String> = None;
    let mut puerto_actual: Option<(String, String)> = None; // (protocolo, puertoid)
    let mut estado_actual: Option<String> = None;
    let mut buffer = Vec::new();

    loop {
        match lector.read_event_into(&mut buffer) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => match e.name().as_ref() {
                b"port" => {
                    let mut protocolo = String::new();
                    let mut portid = String::new();
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"protocol" => {
                                protocolo = String::from_utf8_lossy(&attr.value).to_string()
                            }
                            b"portid" => portid = String::from_utf8_lossy(&attr.value).to_string(),
                            _ => {}
                        }
                    }
                    puerto_actual = Some((protocolo, portid));
                    estado_actual = None;
                }
                b"state" if puerto_actual.is_some() => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"state" {
                            estado_actual = Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                }
                b"service" if puerto_actual.is_some() => {
                    let mut servicio = String::new();
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"name" {
                            servicio = String::from_utf8_lossy(&attr.value).to_string();
                        }
                    }
                    if let (Some((protocolo, portid)), Some(estado)) =
                        (&puerto_actual, &estado_actual)
                    {
                        puertos.push(serde_json::json!({
                            "protocolo": protocolo,
                            "puerto": portid,
                            "estado": estado,
                            "servicio": servicio,
                        }));
                    }
                }
                b"osmatch" if so_detectado.is_none() => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"name" {
                            so_detectado = Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => {
                log::warn!("Error parseando XML de nmap (se conserva el XML crudo igual): {}", e);
                break;
            }
            _ => {}
        }
        buffer.clear();
    }

    serde_json::json!({
        "host": host,
        "puertos_abiertos": puertos,
        "so_detectado": so_detectado,
        "xml_crudo": xml,
    })
}

/// Loop periódico OPCIONAL: si se define `NMAP_HOSTS`
/// ("192.168.1.1,192.168.1.10"), escanea esos hosts cada
/// `NMAP_INTERVALO_SEGUNDOS` (default 300s = 5 min). Si no se define,
/// el escaneo solo ocurre bajo demanda vía `escanear_host` desde el API
/// (más razonable para nmap: escanear cada pocos minutos toda la red es
/// ruidoso; normalmente se prefiere "bajo demanda" desde el botón del
/// frontend).
pub async fn iniciar_escaner_nmap(pool: PgPool) -> std::io::Result<()> {
    let hosts: Vec<String> = env::var("NMAP_HOSTS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if hosts.is_empty() {
        log::info!(
            "Escáner Nmap: NMAP_HOSTS no está definido. Solo disponible bajo \
             demanda vía POST /api/nmap/escanear."
        );
        return Ok(());
    }

    let intervalo: u64 = env::var("NMAP_INTERVALO_SEGUNDOS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);

    log::info!(
        "Escáner Nmap periódico activo: {} host(s), cada {}s",
        hosts.len(),
        intervalo
    );

    loop {
        for host in &hosts {
            if let Err(e) = escanear_host(&pool, host).await {
                log::error!("Error escaneando {} con nmap: {}", host, e);
            }
        }
        tokio::time::sleep(Duration::from_secs(intervalo)).await;
    }
}