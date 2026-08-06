//! Módulo de pruebas de conectividad (ping ICMP).
//!
//! Usa el binario `ping` del sistema (ya instalado en el contenedor vía
//! `iputils-ping`, ver Dockerfile.backend) en vez de manejar sockets ICMP
//! crudos directamente en Rust. ICMP requiere privilegios especiales
//! (CAP_NET_RAW) para abrir un socket raw; el binario `ping` del sistema
//! ya trae ese permiso resuelto sin que tengamos que correr el proceso
//! completo como root (recuerden que el contenedor corre como `appuser`,
//! no root -- ver Dockerfile.backend).

use tokio::process::Command;

/// Resultado de una prueba de ping a un host.
pub struct ResultadoPing {
    pub en_linea: bool,
    pub latencia_ms: Option<String>,
}

pub async fn probar_conexion(host: &str) -> Result<ResultadoPing, String> {
    // -c 1: un solo paquete ICMP.
    // -W 2: máximo 2 segundos de espera por respuesta -- evita que un
    // host caído deje la petición HTTP colgada mucho tiempo.
    let salida = Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg("-W")
        .arg("2")
        .arg(host)
        .output()
        .await
        .map_err(|e| format!("no se pudo ejecutar ping: {}", e))?;

    let en_linea = salida.status.success();
    let texto = String::from_utf8_lossy(&salida.stdout).to_string();

    // Extrae "time=12.3 ms" de la salida de ping sin traer una crate de
    // regex solo para esto.
    let latencia_ms = texto
        .split("time=")
        .nth(1)
        .and_then(|resto| resto.split_whitespace().next())
        .map(|s| s.trim_end_matches("ms").to_string());

    Ok(ResultadoPing {
        en_linea,
        latencia_ms,
    })
}
