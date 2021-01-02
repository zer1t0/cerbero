use std::fmt;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CredFormat {
    Krb,
    Ccache,
}

impl CredFormat {
    pub fn contrary(&self) -> Self {
        match self {
            Self::Krb => Self::Ccache,
            Self::Ccache => Self::Krb,
        }
    }

    pub fn from_file_extension(filename: &str) -> Option<Self> {
        if filename.ends_with(".krb") || filename.ends_with(".kirbi") {
            return Some(Self::Krb);
        }

        if filename.ends_with(".ccache") {
            return Some(Self::Ccache);
        }

        return None;
    }
}

impl fmt::Display for CredFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ccache => write!(f, "ccache"),
            Self::Krb => write!(f, "krb"),
        }
    }
}
