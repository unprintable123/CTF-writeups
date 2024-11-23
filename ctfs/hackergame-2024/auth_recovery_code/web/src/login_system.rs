use actix_web::{web, HttpRequest, HttpResponse, Responder};
use base64::Engine;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::aead::{determinanistic_nonce, AeadCipher, CipherText, User, UserInput, ENCODER, DECODER};
use once_cell::sync::Lazy;
use rand::Rng;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserInfo {
    username: String,
    admin: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RecoveryInput {
    pub recovery_code: String,
    pub new_password: String,
    pub super_mode: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct RegisterdAccountInfo {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    pub recovery_code: String,
}

static ADMIN_PIN: Lazy<[u8; 6]> = Lazy::new(|| {
    let mut key = [0u8; 6];
    for i in 0..6 {
        key[i] = OsRng.gen_range(b'0'..b'2');
    }
    println!("ADMIN_PIN: {:?}", key);
    key
});

static ADMIN_USERNAME: Lazy<[u8; 22]> = Lazy::new(|| {
    let mut key = [0u8; 22];
    key[..6].copy_from_slice(b"ADMIN_");
    for i in 6..22 {
        key[i] = OsRng.gen_range(b'0'..=b'9');
    }
    key
});

static SUPER_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut key = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(ADMIN_USERNAME.as_ref());
    hasher.update(ADMIN_PIN.as_ref());
    key.copy_from_slice(&hasher.finalize());
    key
});


static SECRET_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut key: [u8; 32] = [0u8; 32];
    OsRng.fill(&mut key);
    key
});

const ADMID_AD: &[u8] = b"admin=true";
const MAX_RECOVERY_TIMES: usize = 30;
pub type UserStore = Arc<Mutex<HashMap<Vec<u8>, CipherText>>>;


pub fn init_server_admin(new_password: &str, user_store: &UserStore) {
    let mut users = user_store.lock().unwrap();
    // change the super admin password
    let admin = User {
        username: ADMIN_USERNAME.to_vec(),
        password: new_password.as_bytes().to_vec(),
    };
    let mut ae_cipher = AeadCipher::new(&SECRET_KEY, &admin);
    let credential = ae_cipher.encrypt(&admin.username, true);
    users.insert(admin.username.clone(), credential);
}

pub async fn login(user: web::Json<UserInput>, user_store: web::Data<UserStore>) -> impl Responder {
    let users = user_store.lock().unwrap();
    let mut aead0 = AeadCipher::from_key(&SECRET_KEY);
    let user = User::from(user.into_inner());

    if let Some(credential) = users.get(&user.username) {
        let nonce = determinanistic_nonce(&user).to_vec();
        if nonce == credential.nonce && aead0.decrypt(&credential).unwrap() == user.username {
            let claims = Claims {
                sub: ENCODER.encode(&user.username),
                exp: 10000000000,
            };
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(SECRET_KEY.as_ref()),
            )
            .unwrap();
            // if the user is Super Admin, return content in flag.txt
            let bonus = if user.username == ADMIN_USERNAME.as_ref() {
                std::fs::read_to_string("/flag2").unwrap_or("flag2 not found, please contact admin".to_string())
            }
            else if credential.ad == ADMID_AD {
                // if not flag file, set "flag1 not found, please contact admin"
                std::fs::read_to_string("/flag1").unwrap_or("flag1 not found, please contact admin".to_string())
            } else {
                "You are not an admin".to_string()
            };
            return HttpResponse::Ok().json((token, bonus));
        } else {
            return HttpResponse::Unauthorized().json("Invalid credentials");
        }
    }
    HttpResponse::Unauthorized().json("User not found")
}

pub async fn recover_account(
    input: web::Json<RecoveryInput>,
    user_store: web::Data<UserStore>,
    recovered_times: web::Data<Arc<Mutex<usize>>>,
) -> impl Responder {
    // In case that you forget both your username and password.
    let credential = CipherText::from_recovery_code(input.recovery_code.as_str());
    let mut times = recovered_times.lock().unwrap();
    if *times >= MAX_RECOVERY_TIMES {
        return HttpResponse::Forbidden().finish();
    }
    *times += 1;
    let mut aead0 = if input.super_mode {
        AeadCipher::from_key(&SUPER_KEY)
    } else {
        AeadCipher::from_key(&SECRET_KEY)
    };

    // recover username from recovery code
    let username: Vec<u8> = match aead0.decrypt(&credential) {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::Unauthorized().finish();
        }
    };
    let mut users = user_store.lock().unwrap();
    // look up the user
    if let Some(server_credential) = users.get(&username) {
        // Check nonce if not in super mode.
        // In super mode, the super user can recover/reset any account using the superkey
        // without the knowledge of the original password (or nonce).
        if !input.super_mode && server_credential.nonce != credential.nonce {
            // expired recovery code
            return HttpResponse::Unauthorized().finish();
        }
        // update the user info
        let user = User {
            username: username.clone(),
            password: input.new_password.as_bytes().to_vec(),
        };
        // create a new credential
        let mut ae_cipher = AeadCipher::new(&SECRET_KEY, &user);
        let new_credential = ae_cipher.encrypt(&username, credential.ad == ADMID_AD);
        let new_recovery_code = new_credential.recovery_code();
        users.insert(user.username.clone(), new_credential);

        // return the new recovery code
        let info = RegisterdAccountInfo {
            username: username,
            password: input.new_password.as_bytes().to_vec(),
            recovery_code: new_recovery_code,
        };
        return HttpResponse::Ok().json(info);
    }
    HttpResponse::NotFound().finish()
}

pub async fn register(
    user: web::Json<UserInput>,
    user_store: web::Data<UserStore>,
) -> impl Responder {
    // check if user already exists
    let mut users = user_store.lock().unwrap();
    let new_user = User::from(user.into_inner());
    if users.contains_key(&new_user.username) {
        return HttpResponse::Conflict().finish();
    }
    let mut ae_cipher = AeadCipher::new(&SECRET_KEY, &new_user);
    let credential = ae_cipher.encrypt(&new_user.username, false);
    let recovery_code = credential.recovery_code();
    users.insert(new_user.username.clone(), credential);
    HttpResponse::Ok().json(recovery_code)
}

pub async fn users(req: HttpRequest, user_store: web::Data<UserStore>) -> impl Responder {
    let auth_header = req.headers().get("Authorization");
    if let Some(auth_header) = auth_header {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let validation = Validation::default();
                let token_data = decode::<Claims>(
                    &token,
                    &DecodingKey::from_secret(SECRET_KEY.as_ref()),
                    &validation,
                );
                if let Ok(token_data) = token_data {
                    let claims = token_data.claims;
                    let current_user = DECODER.decode(claims.sub.as_bytes()).unwrap();
                    let users = user_store.lock().unwrap();
                    if let Some(current_credential) = users.get(&current_user) {
                        let is_current_user_admin = current_credential.ad == ADMID_AD;
                        let current_user_info = UserInfo {
                            username: ENCODER.encode(current_user),
                            admin: is_current_user_admin,
                        };
                        // list all users if user is admin
                        let mut user_list = Vec::new();
                        for (username, credential) in users.iter() {
                            let is_admin= credential.ad == ADMID_AD;
                            if is_current_user_admin || !is_admin {
                                let user_info = UserInfo {
                                    username: ENCODER.encode(username),
                                    admin: is_admin,
                                };
                                user_list.push(user_info);
                            }
                        }
                        return HttpResponse::Ok().json((current_user_info, user_list));
                    }
                    // user not find 404
                    return HttpResponse::NotFound().finish();
                }
            }
        }
    }
    HttpResponse::Unauthorized().finish()
}

pub async fn index(tmpl: web::Data<tera::Tera>) -> impl Responder {
    let s = tmpl.render("index.html", &tera::Context::new()).unwrap();
    HttpResponse::Ok().content_type("text/html").body(s)
}

pub async fn users_page(tmpl: web::Data<tera::Tera>) -> impl Responder {
    let s = tmpl.render("users.html", &tera::Context::new()).unwrap();
    HttpResponse::Ok().content_type("text/html").body(s)
}
