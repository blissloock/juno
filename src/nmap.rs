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
    let mut estado_host: Option<String> = None;
    let mut puerto_actual: Option<(String, String)> = None; // (protocolo, puertoid)
    let mut estado_actual: Option<String> = None;
    let mut buffer = Vec::new();

    loop {
        match lector.read_event_into(&mut buffer) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => match e.name().as_ref() {
                b"status" if estado_host.is_none() => {
                    // <status state="up"|"down"/> dentro de <host>: nos dice
                    // si el equipo respondió al descubrimiento de nmap,
                    // independientemente de si tiene puertos abiertos.
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"state" {
                            estado_host = Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                }
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
        "estado_host": estado_host,
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

/// Escanea un rango de red completo (notación CIDR, ej. "192.168.1.0/24")
/// con un ping-sweep (`nmap -sn`, sin escaneo de puertos -- mucho más
/// rápido que un escaneo completo cuando son ~254 hosts) y agrega
/// automáticamente como dispositivo cualquier host que responda y que
/// todavía no esté registrado en `dispositivos`. Nunca modifica ni
/// duplica los que el usuario ya dio de alta a mano (usa UNIQUE(ip) para
/// eso, ver migrations/0003_dispositivos.sql): si un host descubierto ya
/// existe, simplemente se cuenta como "ya registrado" y se deja como
/// está.
pub async fn descubrir_red(pool: &PgPool, red: &str) -> Result<serde_json::Value, String> {
    validar_cidr(red)?;

    log::info!("Iniciando descubrimiento de red sobre {}", red);

    let salida = Command::new("nmap")
        .arg("-sn") // solo descubrimiento de hosts, sin escanear puertos
        .arg("-oX")
        .arg("-")
        .arg(red)
        .output()
        .await
        .map_err(|e| format!("no se pudo ejecutar nmap: {}", e))?;

    if !salida.status.success() {
        return Err(format!(
            "nmap terminó con error: {}",
            String::from_utf8_lossy(&salida.stderr)
        ));
    }

    let xml = String::from_utf8_lossy(&salida.stdout).to_string();
    let hosts = parsear_xml_descubrimiento(&xml);

    let mut agregados = Vec::new();
    let mut ya_registrados = 0;

    for host in &hosts {
        if host.estado.as_deref() != Some("up") {
            continue;
        }
        let nombre = host
            .hostname
            .clone()
            .unwrap_or_else(|| format!("Dispositivo {}", host.ip));

        match db::crear_dispositivo(pool, &nombre, "Desconocido", &host.ip).await {
            Ok(dispositivo) => agregados.push(dispositivo),
            // El caso normal aquí es violar UNIQUE(ip) porque el host ya
            // estaba registrado -- no es un error real, solo significa
            // que no hay nada nuevo que agregar para esa IP.
            Err(_) => ya_registrados += 1,
        }
    }

    log::info!(
        "Descubrimiento de red completo sobre {}: {} host(s) activos, {} agregado(s), {} ya registrado(s)",
        red,
        hosts.len(),
        agregados.len(),
        ya_registrados
    );

    Ok(serde_json::json!({
        "red_escaneada": red,
        "hosts_detectados": hosts.len(),
        "agregados": agregados,
        "ya_registrados": ya_registrados,
    }))
}

/// Por seguridad, no se permite escanear rangos gigantescos por accidente
/// (ej. alguien escribe algo como "10.0.0.0/8" sin querer, que son
/// millones de hosts). Se limita a /16 como mínimo, que ya es generoso
/// (65 mil hosts) para cualquier red doméstica o de laboratorio.
fn validar_cidr(red: &str) -> Result<(), String> {
    let prefijo: u8 = red
        .split('/')
        .nth(1)
        .ok_or_else(|| "Formato inválido, usa notación CIDR (ej. 192.168.1.0/24)".to_string())?
        .parse()
        .map_err(|_| "Prefijo CIDR inválido".to_string())?;

    if prefijo < 16 {
        return Err(
            "Por seguridad, no se permiten rangos mayores a /16 (demasiados hosts)".to_string(),
        );
    }
    Ok(())
}

struct HostDescubierto {
    ip: String,
    hostname: Option<String>,
    estado: Option<String>,
}

/// Parsea el XML de un `nmap -sn` sobre un rango: a diferencia de
/// `parsear_xml_nmap` (que asume un solo <host>), aquí puede haber
/// decenas de bloques <host>, uno por cada IP del rango que nmap alcanzó
/// a evaluar.
fn parsear_xml_descubrimiento(xml: &str) -> Vec<HostDescubierto> {
    let mut lector = Reader::from_str(xml);
    lector.trim_text(true);

    let mut hosts = Vec::new();
    let mut ip_actual: Option<String> = None;
    let mut hostname_actual: Option<String> = None;
    let mut estado_actual: Option<String> = None;
    let mut dentro_de_host = false;
    let mut buffer = Vec::new();

    loop {
        match lector.read_event_into(&mut buffer) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"host" => {
                dentro_de_host = true;
                ip_actual = None;
                hostname_actual = None;
                estado_actual = None;
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"host" => {
                if dentro_de_host {
                    if let Some(ip) = ip_actual.take() {
                        hosts.push(HostDescubierto {
                            ip,
                            hostname: hostname_actual.take(),
                            estado: estado_actual.take(),
                        });
                    }
                }
                dentro_de_host = false;
            }
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) if dentro_de_host => {
                match e.name().as_ref() {
                    b"status" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"state" {
                                estado_actual =
                                    Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                    }
                    b"address" => {
                        let mut tipo_addr = String::new();
                        let mut valor = String::new();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"addrtype" => {
                                    tipo_addr = String::from_utf8_lossy(&attr.value).to_string()
                                }
                                b"addr" => valor = String::from_utf8_lossy(&attr.value).to_string(),
                                _ => {}
                            }
                        }
                        // Solo nos interesa la IPv4; nmap también reporta
                        // la MAC como otro <address> distinto cuando el
                        // ARP scan funciona (misma subred + privilegios).
                        if tipo_addr == "ipv4" && ip_actual.is_none() {
                            ip_actual = Some(valor);
                        }
                    }
                    b"hostname" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"name" && hostname_actual.is_none() {
                                hostname_actual =
                                    Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                log::warn!("Error parseando XML de descubrimiento de red: {}", e);
                break;
            }
            _ => {}
        }
        buffer.clear();
    }

    hosts
}
