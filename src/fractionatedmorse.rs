//! TODO
use common::cipher::Cipher;
use common::alphabet;
use common::keygen::generate_keyed_alphabet;

const MORSE_ALPHABET: [&str; 36] = [".-", "-...", "-.-.", "-..", ".", "..-.", "--.", "....",
"..", ".---", "-.-", ".-..", "--", "-.", "---", ".--.", "--.-", ".-.", "...", "-", "..-", "...-",
".--", "-..-", "-.--", "--..", ".----", "..---", "...--", "....-", ".....", "_....", "--...",
"---..", "----.", "-----"];

const FRAC_MORSE_ALPHABET: [&str; 26] = ["...", "..-", "..|", ".-.", ".--", ".-|", ".|.", ".|-",
".||", "-..", "-.-", "-.|", "--.", "---", "--|", "-|.", "-|-", "-||", "|..", "|.-", "|.|", "|-.",
"|--", "|-|", "||.", "||-"];


/// A Fractionated Morse cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct FractionatedMorse {
    keyed_alphabet: String,
}

impl Cipher for FractionatedMorse {
    type Key = String;
    type Algorithm = FractionatedMorse;

    /// Initialise a Fractionated Morse cipher given a specific key.
    ///
    /// Will return `Err` if the key contains non-alphabetic symbols.
    fn new(key: String) -> Result<FractionatedMorse, &'static str> {
        for c in key.chars() {
            //Keys can only contain characters in the known alphabet
            if alphabet::find_position(c).is_none() {
                return Err("Invalid key. Fractionated Morse keys cannot contain non-alphabetic symbols.");
            }
        }

        let keyed_alphabet = generate_keyed_alphabet(&key, false)?;
        Ok(FractionatedMorse { keyed_alphabet: keyed_alphabet })
    }

    /// Encrypt a message using a Fractionated Morse cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Encryption method: TODO
        let morse = FractionatedMorse::encrypt_morse(message.to_string())?;
        println!("{}", morse);
        let ciphertext = FractionatedMorse::decrypt_frac_morse(&self.keyed_alphabet, morse)?;
        Ok(ciphertext)
    }

    /// Decrypt a message using a Fractionated Morse cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// ```
    fn decrypt(&self, cipher_text: &str) -> Result<String, &'static str> {
        Ok("TODO".to_string())
    }
}

impl FractionatedMorse {
    /// TODO
    fn encrypt_morse(message: String) -> Result<String, &'static str> {
        
        let mut morse = String::new();

        for c in message.chars() {
            match alphabet::find_position(c) {
                Some(pos) => {
                    morse.extend(MORSE_ALPHABET[pos].chars());
                    morse.push('|');
                },
                None => {
                    return Err("Invalid message. Please strip any whitespace or non-alphabetic symbols.")
                }
            }
        }

        // The message ends with two seperators
        morse.push('|');

        Ok(morse)
    }

    /// TODO
    fn decrypt_frac_morse(keyed_alphabet: &str, mut message: String) -> Result<String, &'static str> {
        let mut result = String::new();

        while message.len() % 3 != 0 {
            message.push('.');
        }

        for trigraph in message.as_bytes().chunks(3) {
            if let Some(pos) = FRAC_MORSE_ALPHABET.iter().position(|&t| t.as_bytes() == trigraph) {
                result.push(keyed_alphabet.chars().nth(pos).unwrap());
            } else {
                return Err("Fractionated morse trigraph not present in alphabet")
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_test() {
        let message = "attackatdawn";
        let f = FractionatedMorse::new(String::from("key")).unwrap();
        assert_eq!("cpsujiswhsspg", f.encrypt(message).unwrap());
    }
}
