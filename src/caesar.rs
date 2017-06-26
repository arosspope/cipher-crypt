use common::alphabet::LOWER_ALPHABET;
use common::alphabet::UPPER_ALPHABET;

pub struct Caesar {
    shift: usize,
}

impl Caesar {
    pub fn encrypt(&self, message: &str) -> String {
        /*  Encryption of a letter:
                    E(x) = (x + n) mod 26
            Where;  x = position of letter in alphabet
                    n = shift factor (or key)
        */
        Caesar::substitute(message, |idx| (idx + self.shift) % 26)
    }

    pub fn decrypt(&self, cipher_text: &str) -> String {
        /*  Decryption of a letter:
                    D(x) = (x - n) mod 26
            Where;  x = position of letter in alphabet
                    n = shift factor (or key)
        */
        let calc_letter_pos = |idx| {
            let a: isize = idx as isize - self.shift as isize;
            (((a % 26) + 26) % 26) as usize
            //Rust does not natievly support negative wrap around modulo operations
        };
        Caesar::substitute(cipher_text, calc_letter_pos)
    }

    fn substitute<F>(text: &str, substitute_index: F) -> String
        where F: Fn(usize) -> usize
    {
        let mut substituted_text = String::new();

        for l in text.chars() {
            //Look for letter in the lowercase alphabet
            let idx = LOWER_ALPHABET.iter().position(|&x| x == l);
            match idx {
                Some(i) => {
                    substituted_text.push(LOWER_ALPHABET[substitute_index(i)]);
                    continue;   //process the next letter
                },
                None => ()
            }

            //else look for letter in the uppercase alphabet
            let idx = UPPER_ALPHABET.iter().position(|&x| x == l);
            match idx {
                Some(i) => {
                    substituted_text.push(UPPER_ALPHABET[substitute_index(i)]);
                    continue;
                },
                None => substituted_text.push(l),   //Just push non-alphabetic chars 'as is'
            }
        }

        substituted_text
    }

    pub fn new(shift: usize) -> Result<Caesar, &'static str> {
        if shift >= 1 && shift <= 26 {
            return Ok(Caesar {shift: shift});
        }

        Err("Invalid shift factor. Must be in the range 1-26")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_message() {
        let c = Caesar::new(2).unwrap();
        assert_eq!("Cvvcem cv fcyp!", c.encrypt("Attack at dawn!"));
    }

    #[test]
    fn decrypt_message() {
        let c = Caesar::new(2).unwrap();
        assert_eq!("Attack at dawn!", c.decrypt("Cvvcem cv fcyp!"));
    }

    #[test]
    fn with_emoji(){
        let c = Caesar::new(3).unwrap();
        let message = "Peace, Freedom and Liberty! 🗡️";
        let encrypted = c.encrypt(message);
        let decrypted = c.decrypt(&encrypted);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn exhaustive_encrypt(){
        //Test with every possible shift combination
        let message = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        for i in 1..26 {
            let c = Caesar::new(i).unwrap();
            let encrypted = c.encrypt(message);
            let decrypted = c.decrypt(&encrypted);
            assert_eq!(decrypted, message);
        }
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
