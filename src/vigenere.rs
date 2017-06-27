use std::iter;
use common::alphabet::LOWER_ALPHABET;
use common::alphabet::UPPER_ALPHABET;

pub struct Vigenere {
    key: String,
}

impl Vigenere {
    pub fn encrypt(&self, message: &str) -> String {
        let encipher_key = self.fit_key(message.len());

        String::from("encrypt")
    }

    pub fn decrypt(&self, cipher_text: &str) -> String {
        let decipher_key = self.fit_key(cipher_text.len());

        String::from("decrypt")
    }

    fn fit_key(&self, msg_length: usize) -> String {
        let key_copy = self.key.clone();

        if self.key.len() > msg_length {
            return key_copy;
        }

        let mut repeated_key = iter::repeat(key_copy).take((msg_length % self.key.len()) + 1)
            .collect::<String>();

        repeated_key.truncate(msg_length);
        repeated_key
    }

    pub fn new(key: String) -> Result<Vigenere, &'static str> {
        //Keys can only contain characters in the known alphabet
        for c in key.chars(){
            if LOWER_ALPHABET.iter().find(|&&a| a == c).is_none() &&
                UPPER_ALPHABET.iter().find(|&&a| a == c).is_none()
            {
                return Err("Invalid key. Vigenere keys cannot contain symbols.");
            }
        }

        Ok(Vigenere { key: key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_smaller_key() {
        let message = "We are under seige!"; //19 character message
        let v = Vigenere::new(String::from("lemon")).unwrap(); //key length of 5

        assert_eq!("lemonlemonlemonlemo", v.fit_key(message.len()));
    }

    #[test]
    fn fit_larger_key() {
        let message = "hi";
        let v = Vigenere::new(String::from("lemon")).unwrap();

        assert_eq!("lemon", v.fit_key(message.len()));
    }

    #[test]
    fn valid_key() {
        assert!(Vigenere::new(String::from("Lemon")).is_ok());
    }

    #[test]
    fn key_with_symbols() {
        assert!(Vigenere::new(String::from("!em@n")).is_err());
    }
}
