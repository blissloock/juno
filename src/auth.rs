//! Autenticación: hashing de contraseñas (Argon2id) y tokens de sesión (JWT).
//!
//! Decisiones de seguridad de este módulo, por si les preguntan en la
//! evaluación por qué se hizo así:
//! - Las contraseñas NUNCA se guardan ni se comparan en texto plano; se usa
//!   Argon2id (ganador de la Password Hashing Competition), con una sal
//!   aleatoria distinta por usuario generada automáticamente por el crate.
//! - El secreto para firmar los JWT sale de una variable de entorno
//!   (`JWT_SECRET`), nunca hardcodeado en el código fuente.
//! - Los tokens expiran (`EXP_HORAS`): si un token se filtra, el daño tiene
//!   fecha de caducidad en vez de ser válido para siempre.

use actix_web::{dev::Payload, error::ErrorUnauthorized, Error, FromRequest, HttpRequest};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use futures_util::future::{ready, Ready};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;

const EXP_HORAS: i64 = 8;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // id del usuario
    rol: String,
    exp: usize,
}

fn jwt_secret() -> String {
    env::var("JWT_SECRET").expect(
        "La variable de entorno JWT_SECRET no está definida. Genera una con: openssl rand -hex 32",
    )
}

/// Calcula el hash Argon2id de una contraseña en texto plano. El resultado
/// (que ya incluye la sal y los parámetros del algoritmo) es lo único que
/// se guarda en la base de datos.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Verifica una contraseña contra su hash almacenado.
pub fn verificar_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Genera un JWT firmado para un usuario ya autenticado.
pub fn generar_token(usuario_id: i32, rol: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let exp = (chrono::Utc::now() + chrono::Duration::hours(EXP_HORAS)).timestamp() as usize;
    let claims = Claims {
        sub: usuario_id.to_string(),
        rol: rol.to_string(),
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret().as_bytes()),
    )
}

fn verificar_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let datos = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret().as_bytes()),
        &Validation::default(),
    )?;
    Ok(datos.claims)
}

/// Extractor de Actix: agregar `usuario: AuthenticatedUser` como argumento
/// de cualquier handler lo vuelve automáticamente protegido. Actix
/// rechaza la petición con 401 antes de ejecutar el cuerpo del handler si
/// no viene un JWT válido en el header `Authorization: Bearer <token>`.
pub struct AuthenticatedUser {
    pub usuario_id: i32,
    pub rol: String,
}

impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let resultado = req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or_else(|| ErrorUnauthorized("Falta el header Authorization"))
            .and_then(|token| {
                verificar_token(token).map_err(|_| ErrorUnauthorized("Token inválido o expirado"))
            })
            .and_then(|claims| {
                claims
                    .sub
                    .parse::<i32>()
                    .map(|id| AuthenticatedUser {
                        usuario_id: id,
                        rol: claims.rol,
                    })
                    .map_err(|_| ErrorUnauthorized("Token inválido"))
            });

        ready(resultado)
    }
}
