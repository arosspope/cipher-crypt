use common::alphabet::LOWER_ALPHABET;
use common::alphabet::UPPER_ALPHABET;

pub struct Vigenere {
    key: str,
}

impl Caesar {
    pub fn encrypt(&self, message: &str) -> String {
    }

    pub fn decrypt(&self, cipher_text: &str) -> String {
    }

    pub fn new(key: str) -> Result<Vigenere, &'static str> {
        Ok(Vigenere { key: key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
