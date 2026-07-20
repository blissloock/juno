//! Utilidad de línea de comandos para crear usuarios (típicamente, el
//! primer admin del dashboard).
//!
//! Por qué esto es un binario aparte y NO un endpoint HTTP: crear un
//! usuario es una operación sensible. Si existiera como endpoint público
//! (aunque fuera "solo la primera vez"), sería una superficie de ataque
//! extra que alguien podría intentar explotar antes de que el equipo
//! configure el primer admin. Ejecutarlo por línea de comandos significa
//! que solo alguien con acceso a la máquina/contenedor puede crear cuentas.
//!
//! Uso local:
//!   cargo run --bin crear_admin -- <username> <password> [rol]
//!
//! Ejemplo:
//!   cargo run --bin crear_admin -- admin "MiPasswordSegura123!" admin
//!
//! Uso dentro del contenedor ya construido (una vez que exista el
//! binario `crear_admin` junto a `backend_bin`):
//!   docker compose exec backend ./crear_admin admin "MiPasswordSegura123!" admin

use ProyectoIntegrador::{auth, db};

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Uso: crear_admin <username> <password> [rol=admin]");
        std::process::exit(1);
    }

    let username = &args[1];
    let password = &args[2];
    let rol = args.get(3).map(|s| s.as_str()).unwrap_or("admin");

    // Validación mínima de robustez de contraseña. No sustituye una
    // política completa, pero evita el error más común: contraseñas
    // triviales para la cuenta más privilegiada del sistema.
    if password.len() < 8 {
        eprintln!("La contraseña debe tener al menos 8 caracteres.");
        std::process::exit(1);
    }

    let pool = db::crear_pool()
        .await
        .expect("No fue posible conectar a la base de datos. Verifica DATABASE_URL.");

    // Por si esta utilidad se corre antes de haber arrancado el backend
    // una sola vez, nos aseguramos de que las tablas ya existan.
    db::ejecutar_migraciones(&pool)
        .await
        .expect("No fue posible aplicar las migraciones de la base de datos.");

    let existe = db::obtener_usuario_por_username(&pool, username)
        .await
        .expect("Error consultando la base de datos");

    if existe.is_some() {
        eprintln!("Ya existe un usuario con el username '{}'.", username);
        std::process::exit(1);
    }

    let hash = auth::hash_password(password).expect("Error calculando el hash de la contraseña");

    db::crear_usuario(&pool, username, &hash, rol)
        .await
        .expect("Error insertando el usuario en la base de datos");

    println!(
        "Usuario '{}' creado correctamente con rol '{}'.",
        username, rol
    );
}
