use std::ascii::AsciiExt;

const ALPHABET: [char; 26] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

pub struct Caesar {
    key: usize,
}

impl Caesar {
    pub fn encrypt(&self, cipher_text: &str) -> String {
        /*  Encryptiong of a letter:
                    E(x) = (x + n) mod 26
            Where;  x = position of letter in alphabet
                    n = shift factor (or key)
        */
        Caesar::cipher(cipher_text, |i| (i + self.key) % 26)
    }

    pub fn decrypt(&self, cipher_text: &str) -> String {
        /*  Decryption of a letter:
                    D(x) = (x - n) mod 26
            Where;  x = position of letter in alphabet
                    n = shift factor (or key)
        */
        Caesar::cipher(cipher_text, |i| i.saturating_sub(self.key) % 26)
    }

    fn cipher<F>(message: &str, operation: F) -> String
        where F: Fn(usize) -> usize
    {
        let mut ciphered_text = String::new();

        for l in message.chars() {
            //Find the index of the potential
            let index = ALPHABET.iter().position(|&x| x == l.to_ascii_lowercase());

            match index {
                Some(i) => ciphered_text.push(ALPHABET[operation(i)]),
                None => ciphered_text.push(l),
            }
        }

        ciphered_text
    }

    pub fn new(key: usize) -> Caesar {
        if !(key > 0 && key < 27) {
            panic!("Expecting a number between 1 and 26"); //TODO: return result
        }

        Caesar { key: key }
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
    fn key_to_small() {
        let c = Caesar::new(0);
    }

    #[test]
    #[should_panic]
    fn key_to_big() {
        let c = Caesar::new(27);
    }
}
