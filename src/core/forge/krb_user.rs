
// Struct to package the user identity with name and domain
#[derive(Clone, Debug)]
pub struct KerberosUser {
    pub name: String,
    pub realm: String,
}

impl KerberosUser {
    pub fn new(name: String, realm: String) -> Self {
        return Self { name, realm };
    }
}
