use std::convert::TryFrom;
use std::fmt;

// Struct to package the user identity with name and domain
#[derive(Clone, Debug)]
pub struct KrbUser {
    pub realm: String,
    pub name: String,
}

impl KrbUser {
    pub fn new(name: String, realm: String) -> Self {
        return Self { name, realm };
    }
}

impl fmt::Display for KrbUser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.realm, self.name)
    }
}

impl TryFrom<&str> for KrbUser {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> =
            value.split(|c| ['/', '\\'].contains(&c)).collect();

        if parts.len() != 2 || parts[0].len() == 0 || parts[1].len() == 0 {
            return Err(format!(
                "Invalid user '{}', it must be <domain>/<username>",
                value
            ));
        }

        return Ok(KrbUser::new(
            parts[1].to_string(),
            parts[0].to_string(),
        ));
    }
}

impl TryFrom<&String> for KrbUser {
    type Error = String;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        return Self::try_from(value.as_str());
    }
}

impl TryFrom<String> for KrbUser {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        return Self::try_from(&value);
    }
}
