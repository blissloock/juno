//! Librería de Juno.
//!
//! Se expone como lib (además del binario en `main.rs`) para que
//! utilidades de línea de comandos como `src/bin/crear_admin.rs` puedan
//! reutilizar `db` y `auth` sin duplicar código.

pub mod alerts;
pub mod auth;
pub mod db;
pub mod ids;
pub mod netflow;
pub mod nmap;
pub mod ping;
pub mod snmp;
