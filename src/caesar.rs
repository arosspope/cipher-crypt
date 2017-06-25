use std::ascii::AsciiExt;

const ALPHABET: [char; 26] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

pub struct Caesar {
    key: usize,
}

impl Caesar {
    pub fn encrypt(&self, message: &str) -> String {
        /*  Encryption of a letter:
                    E(x) = (x + n) mod 26
            Where;  x = position of letter in alphabet
                    n = shift factor (or key)
        */
        Caesar::substitute(message, |i| (i + self.key) % 26)
    }

    pub fn decrypt(&self, cipher_text: &str) -> String {
        /*  Decryption of a letter:
                    D(x) = (x - n) mod 26
            Where;  x = position of letter in alphabet
                    n = shift factor (or key)
        */
        Caesar::substitute(cipher_text, |i| i.saturating_sub(self.key) % 26)
    }

    fn substitute<F>(text: &str, substitute_index: F) -> String
        where F: Fn(usize) -> usize
    {
        let mut substituted_text = String::new();

        for l in text.chars() {
            let index = ALPHABET.iter().position(|&x| x == l.to_ascii_lowercase());

            match index {
                Some(i) => substituted_text.push(ALPHABET[substitute_index(i)]),
                None => substituted_text.push(l),   //Just push non-alphabetic chars 'as is'
            }
        }

        substituted_text
    }

    pub fn new(key: usize) -> Result<Caesar, &'static str> {
        if key >= 1 && key <= 26 {
            return Ok(Caesar {key: key});
        }

        Err("Invalid key. Key must be in range 1-26")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_message() {
        let c = Caesar::new(2).unwrap();
        assert_eq!("cvvcem cv fcyp!", c.encrypt("Attack at dawn!"));
    }

    #[test]
    fn decrypt_message() {
        let c = Caesar::new(2).unwrap();
        assert_eq!("attack at dawn!", c.decrypt("cvvcem cv fcyp!"));
    }

    #[test]
    fn with_emoji(){
        let c = Caesar::new(3).unwrap();
        let message = "peace, freedom and liberty! 🗡️";
        let encrypted = c.encrypt(message);
        let decrypted = c.decrypt(&encrypted);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn key_to_small() {
        assert!(Caesar::new(0).is_err());
    }

    #[test]
    fn key_to_big() {
        assert!(Caesar::new(27).is_err());
    }
}
