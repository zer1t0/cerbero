
use failure::Fail;
use std::result;

pub type Result<T> = result::Result<T, Error>;

#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "{}", _0)]
    String(String)
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
