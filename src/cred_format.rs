use std::fmt;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CredentialFormat {
    Krb,
    Ccache,
}

impl fmt::Display for CredentialFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ccache => write!(f, "ccache"),
            Self::Krb => write!(f, "krb"),
        }
    }
}
