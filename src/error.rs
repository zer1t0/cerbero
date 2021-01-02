use kerberos_asn1::KrbError;
use kerberos_constants::error_codes;
use std::fmt;
use std::io;
use std::result;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    String(String),
    KrbError(KrbError),
    IOError(String, io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::String(s) => write!(f, "{}", s),
            Error::KrbError(krb_error) => {
                write!(f, "{}", create_krb_error_msg(&krb_error))
            }
            Error::IOError(desc, io_error) => {
                write!(f, "{}: {}", desc, io_error)
            }
        }
    }
}

impl From<String> for Error {
    fn from(error: String) -> Self {
        return Self::String(error);
    }
}

impl From<&str> for Error {
    fn from(error: &str) -> Self {
        return Self::String(error.to_string());
    }
}

impl From<KrbError> for Error {
    fn from(error: KrbError) -> Self {
        return Self::KrbError(error);
    }
}

impl From<(&str, io::Error)> for Error {
    fn from(error: (&str, io::Error)) -> Self {
        return Self::IOError(error.0.into(), error.1);
    }
}

fn create_krb_error_msg(krb_error: &KrbError) -> String {
    let error_string = error_codes::error_code_to_string(krb_error.error_code);
    return format!("Error {}: {}", krb_error.error_code, error_string);
}
