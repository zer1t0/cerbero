use kerberos_crypto::Key;
use std::net::IpAddr;

pub fn is_rc4_key(v: String) -> Result<(), String> {
    Key::from_rc4_key_string(&v).map_err(|_| {
        format!(
            "Invalid RC4 key '{}', must be a string of 32 hexadecimals",
            v
        )
    })?;

    return Ok(());
}

pub fn is_aes_128_key(v: String) -> Result<(), String> {
    Key::from_aes_128_key_string(&v).map_err(|_| {
        format!(
            "Invalid AES-128 key '{}', must be a string of 32 hexadecimals",
            v
        )
    })?;

    return Ok(());
}

pub fn is_aes_256_key(v: String) -> Result<(), String> {
    Key::from_aes_256_key_string(&v).map_err(|_| {
        format!(
            "Invalid AES-256 key '{}', must be a string of 64 hexadecimals",
            v
        )
    })?;

    return Ok(());
}

pub fn is_ip(v: String) -> Result<(), String> {
    v.parse::<IpAddr>()
        .map_err(|_| format!("Invalid IP address '{}'", v))?;
    return Ok(());
}
