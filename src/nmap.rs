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

/// Extrae puertos abiertos, MAC, vendor, hostname y sistema operativo detectado del XML de nmap,
/// e infiere automáticamente el tipo de dispositivo (Router, Switch, PC, Servidor, Impresora, Cámara).
fn parsear_xml_nmap(xml: &str, host: &str) -> serde_json::Value {
    let mut lector = Reader::from_str(xml);
    lector.trim_text(true);

    let mut puertos = Vec::new();
    let mut so_detectado: Option<String> = None;
    let mut estado_host: Option<String> = None;
    let mut mac: Option<String> = None;
    let mut vendor: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut puerto_actual: Option<(String, String)> = None; // (protocolo, puertoid)
    let mut estado_actual: Option<String> = None;
    let mut buffer = Vec::new();

    loop {
        match lector.read_event_into(&mut buffer) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => match e.name().as_ref() {
                b"status" if estado_host.is_none() => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"state" {
                            estado_host = Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                }
                b"address" => {
                    let mut tipo_addr = String::new();
                    let mut addr_val = String::new();
                    let mut vendor_val = String::new();
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"addrtype" => tipo_addr = String::from_utf8_lossy(&attr.value).to_string(),
                            b"addr" => addr_val = String::from_utf8_lossy(&attr.value).to_string(),
                            b"vendor" => vendor_val = String::from_utf8_lossy(&attr.value).to_string(),
                            _ => {}
                        }
                    }
                    if tipo_addr == "mac" {
                        mac = Some(addr_val);
                        if !vendor_val.is_empty() {
                            vendor = Some(vendor_val);
                        }
                    }
                }
                b"hostname" if hostname.is_none() => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"name" {
                            hostname = Some(String::from_utf8_lossy(&attr.value).to_string());
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

    let tipo_inferido = clasificar_dispositivo(
        host,
        vendor.as_deref(),
        hostname.as_deref(),
        so_detectado.as_deref(),
        &puertos,
    );

    serde_json::json!({
        "host": host,
        "estado_host": estado_host,
        "puertos_abiertos": puertos,
        "so_detectado": so_detectado,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "tipo_inferido": tipo_inferido,
        "xml_crudo": xml,
    })
}

/// Infiere el tipo de dispositivo (Router, Switch, PC, Servidor, Impresora, Cámara)
/// evaluando IP, fabricante (MAC vendor), hostname, SO detectado y lista de puertos abiertos.
pub fn clasificar_dispositivo(
    ip: &str,
    vendor: Option<&str>,
    hostname: Option<&str>,
    so_detectado: Option<&str>,
    puertos: &[serde_json::Value],
) -> String {
    let vendor_lower = vendor.unwrap_or("").to_lowercase();
    let host_lower = hostname.unwrap_or("").to_lowercase();
    let so_lower = so_detectado.unwrap_or("").to_lowercase();

    let mut num_puertos = std::collections::HashSet::new();
    let mut servicios = Vec::new();

    for item in puertos {
        if let Some(p_str) = item.get("puerto").and_then(|v| v.as_str()) {
            if let Ok(p_num) = p_str.parse::<u16>() {
                num_puertos.insert(p_num);
            }
        }
        if let Some(s_str) = item.get("servicio").and_then(|v| v.as_str()) {
            servicios.push(s_str.to_lowercase());
        }
    }

    // 1. Impresora (Printer)
    if num_puertos.contains(&631) || num_puertos.contains(&9100) || num_puertos.contains(&515)
        || servicios.iter().any(|s| s.contains("ipp") || s.contains("jetdirect") || s.contains("printer") || s.contains("lpd"))
        || vendor_lower.contains("epson") || vendor_lower.contains("canon") || vendor_lower.contains("brother")
        || vendor_lower.contains("xerox") || vendor_lower.contains("lexmark") || vendor_lower.contains("kyocera") || vendor_lower.contains("ricoh")
    {
        return "Impresora".to_string();
    }

    // 2. Cámara (Camera / CCTV)
    if num_puertos.contains(&554) || num_puertos.contains(&8000) || num_puertos.contains(&8899)
        || servicios.iter().any(|s| s.contains("rtsp") || s.contains("onvif"))
        || vendor_lower.contains("hikvision") || vendor_lower.contains("dahua") || vendor_lower.contains("axis")
        || vendor_lower.contains("reolink") || vendor_lower.contains("amcrest") || vendor_lower.contains("foscam")
        || host_lower.contains("cam") || host_lower.contains("camera") || host_lower.contains("cctv")
    {
        return "Cámara".to_string();
    }

    // 3. Switch
    if host_lower.contains("switch") || host_lower.contains("sw-") || host_lower.contains("-sw")
        || vendor_lower.contains("catalyst") || vendor_lower.contains("procurve")
        || (vendor_lower.contains("cisco") && (num_puertos.contains(&161) || num_puertos.contains(&23)) && !num_puertos.contains(&53))
        || (num_puertos.contains(&161) && num_puertos.contains(&23) && !num_puertos.contains(&80) && !num_puertos.contains(&443))
    {
        return "Switch".to_string();
    }

    // 4. Router (Gateway .1 / .254, DNS 53, DHCP 67/68, RouterOS, Cisco, Ubiquiti, TP-Link, etc.)
    if ip.ends_with(".1") || ip.ends_with(".254")
        || num_puertos.contains(&53) || num_puertos.contains(&67) || num_puertos.contains(&68)
        || host_lower.contains("router") || host_lower.contains("gateway") || host_lower.contains("gw") || host_lower.contains("modem")
        || vendor_lower.contains("mikrotik") || vendor_lower.contains("ubiquiti") || vendor_lower.contains("tp-link")
        || vendor_lower.contains("netgear") || vendor_lower.contains("linksys") || vendor_lower.contains("fortinet")
        || vendor_lower.contains("technicolor") || vendor_lower.contains("arcsady") || vendor_lower.contains("sagemcom")
        || vendor_lower.contains("zte") || vendor_lower.contains("zyxel")
        || so_lower.contains("routeros") || so_lower.contains("openwrt") || so_lower.contains("dd-wrt") || so_lower.contains("cisco ios")
        || (vendor_lower.contains("cisco") && (num_puertos.contains(&80) || num_puertos.contains(&443) || num_puertos.contains(&22)))
    {
        return "Router".to_string();
    }

    // 5. Servidor (Server)
    if num_puertos.contains(&3306) || num_puertos.contains(&5432) || num_puertos.contains(&27017) || num_puertos.contains(&6379) || num_puertos.contains(&1433)
        || (num_puertos.contains(&22) && (num_puertos.contains(&80) || num_puertos.contains(&443) || num_puertos.contains(&8080) || num_puertos.contains(&8443)))
        || host_lower.contains("server") || host_lower.contains("srv") || host_lower.contains("node") || host_lower.contains("cluster")
        || so_lower.contains("server") || so_lower.contains("ubuntu server") || so_lower.contains("debian") || so_lower.contains("redhat") || so_lower.contains("centos") || so_lower.contains("proxmox") || so_lower.contains("esxi")
    {
        return "Servidor".to_string();
    }

    // 6. PC / Laptop / Workstation
    if num_puertos.contains(&445) || num_puertos.contains(&135) || num_puertos.contains(&139) || num_puertos.contains(&3389) || num_puertos.contains(&5353)
        || host_lower.contains("pc") || host_lower.contains("laptop") || host_lower.contains("desktop") || host_lower.contains("win") || host_lower.contains("macbook")
        || vendor_lower.contains("apple") || vendor_lower.contains("intel") || vendor_lower.contains("dell") || vendor_lower.contains("lenovo") || vendor_lower.contains("microsoft") || vendor_lower.contains("realtek")
        || so_lower.contains("windows") || so_lower.contains("mac") || so_lower.contains("ubuntu")
    {
        return "PC".to_string();
    }

    // Fallback inteligente
    if num_puertos.contains(&80) || num_puertos.contains(&443) {
        "Router".to_string()
    } else {
        "PC".to_string()
    }
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
/// todavía no esté registrado en `dispositivos`.
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

        let tipo_inferido = clasificar_dispositivo(
            &host.ip,
            host.vendor.as_deref(),
            host.hostname.as_deref(),
            None,
            &[],
        );

        match db::crear_dispositivo(pool, &nombre, &tipo_inferido, &host.ip).await {
            Ok(dispositivo) => agregados.push(dispositivo),
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
    #[allow(dead_code)]
    mac: Option<String>,
    vendor: Option<String>,
    estado: Option<String>,
}

fn parsear_xml_descubrimiento(xml: &str) -> Vec<HostDescubierto> {
    let mut lector = Reader::from_str(xml);
    lector.trim_text(true);

    let mut hosts = Vec::new();
    let mut ip_actual: Option<String> = None;
    let mut hostname_actual: Option<String> = None;
    let mut mac_actual: Option<String> = None;
    let mut vendor_actual: Option<String> = None;
    let mut estado_actual: Option<String> = None;
    let mut dentro_de_host = false;
    let mut buffer = Vec::new();

    loop {
        match lector.read_event_into(&mut buffer) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"host" => {
                dentro_de_host = true;
                ip_actual = None;
                hostname_actual = None;
                mac_actual = None;
                vendor_actual = None;
                estado_actual = None;
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"host" => {
                if dentro_de_host {
                    if let Some(ip) = ip_actual.take() {
                        hosts.push(HostDescubierto {
                            ip,
                            hostname: hostname_actual.take(),
                            mac: mac_actual.take(),
                            vendor: vendor_actual.take(),
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
                        let mut vendor = String::new();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"addrtype" => {
                                    tipo_addr = String::from_utf8_lossy(&attr.value).to_string()
                                }
                                b"addr" => valor = String::from_utf8_lossy(&attr.value).to_string(),
                                b"vendor" => vendor = String::from_utf8_lossy(&attr.value).to_string(),
                                _ => {}
                            }
                        }
                        if tipo_addr == "ipv4" && ip_actual.is_none() {
                            ip_actual = Some(valor);
                        } else if tipo_addr == "mac" {
                            mac_actual = Some(valor);
                            if !vendor.is_empty() {
                                vendor_actual = Some(vendor);
                            }
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
