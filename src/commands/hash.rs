use crate::Result;
use kerberos_crypto::{aes_hmac_sha1, rc4_hmac_md5, AesSizes};

pub fn hash(realm: &str, username: &str, password: &str) -> Result<()> {
    let rc4_key = rc4_hmac_md5::generate_key_from_string(password);
    let aes_salt = aes_hmac_sha1::generate_salt(realm, username);

    let aes_128_key = aes_hmac_sha1::generate_key_from_string(
        password,
        &aes_salt,
        &AesSizes::Aes128,
    );
    let aes_256_key = aes_hmac_sha1::generate_key_from_string(
        password,
        &aes_salt,
        &AesSizes::Aes256,
    );

    println!("rc4:{:X?}", rc4_key);
    println!("aes128:{:X?}", aes_128_key);
    println!("aes256:{:X?}", aes_256_key);

    return Ok(());
}
