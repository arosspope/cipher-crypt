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

    fn substitute<F>(text: &str, sub_operation: F) -> String
        where F: Fn(usize) -> usize
    {
        let mut substituted_text = String::new();

        for l in text.chars() {
            let index = ALPHABET.iter().position(|&x| x == l.to_ascii_lowercase());

            match index {
                Some(i) => substituted_text.push(ALPHABET[sub_operation(i)]),
                None => substituted_text.push(l),
            }
        }

        substituted_text
    }

    pub fn new(key: usize) -> Result<Caesar, &'static str> {
        if !(key > 0 && key < 27) {
            panic!("Expecting a number between 1 and 26"); //TODO: return result
        }

        Ok(Caesar { key: key })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_message() {
        let c = Caesar::new(2);
        assert_eq!("cvvcem cv fcyp!", c.encrypt("Attack at dawn!"));
    }

    #[test]
    fn decrypt_message() {
        let c = Caesar::new(2);
        assert_eq!("attack at dawn!", c.decrypt("cvvcem cv fcyp!"));
    }

    #[test]
    #[should_panic]
    #[allow(unused)]
    fn key_to_small() {
        let c = Caesar::new(0);
    }

    #[test]
    #[should_panic]
    #[allow(unused)]
    fn key_to_big() {
        let c = Caesar::new(27);
    }
}
