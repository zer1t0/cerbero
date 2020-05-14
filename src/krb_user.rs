

pub struct KerberosUser {
    pub name: String,
    pub realm: String
}


impl KerberosUser {
    pub fn new(name: String, realm: String) -> Self {
        return Self {name, realm};
    }
}
