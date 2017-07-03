//! TODO
use common::cipher::Cipher;
use common::alphabet;
use common::keygen::generate_keyed_alphabet;

const MORSE_ALPHABET: [&str; 36] = [".-", "-...", "-.-.", "-..", ".", "..-.", "--.", "....",
"..", ".---", "-.-", ".-..", "--", "-.", "---", ".--.", "--.-", ".-.", "...", "-", "..-", "...-",
".--", "-..-", "-.--", "--..", ".----", "..---", "...--", "....-", ".....", "-....", "--...",
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
            // Keys can only contain characters in the known alphabet
            // NOT alphanumeric
            if alphabet::find_position(c).is_none() {
                return Err("Invalid key. Fractionated Morse keys cannot contain non-alphanumeric symbols.");
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
        let frac_morse = FractionatedMorse::encrypt_frac_morse(&self.keyed_alphabet, cipher_text.to_string())?;
        let plaintext = FractionatedMorse::decrypt_morse(frac_morse)?;
        Ok(plaintext)
    }
}


impl FractionatedMorse {
    /// TODO
    fn encrypt_morse(message: String) -> Result<String, &'static str> {
        let mut morse = String::new();

        for c in message.chars() {
            match alphabet::find_alphanumeric_position(c) {
                Some(pos) => {
                    morse.extend(MORSE_ALPHABET[pos].chars());
                    morse.push('|');
                },
                None => {
                    return Err("Invalid message. Please strip any whitespace or non-alphanumeric symbols.")
                }
            }
        }

        // The message ends with two seperators
        morse.push('|');

        Ok(morse)
    }

    /// TODO
    fn decrypt_morse(mut message: String) -> Result<String, &'static str> {
        let mut plaintext = String::new();

        // Remove seperators from the beginning of the message
        while message.starts_with('|') {
            message.remove(0);
        }

        for morse_chr in message.split('|') {
            // Message ends with two sperators, which will produce an empty string
            if morse_chr == "" {
                break;
            }

            if let Some(pos) = MORSE_ALPHABET.iter().position(|&t| t == morse_chr) {
                plaintext.push(alphabet::get_alphanumeric_symbol(pos, false).unwrap());
            } else {
                return Err("Unknown morse character found.")
            }
        }

        Ok(plaintext)
    }

    /// TODO
    fn encrypt_frac_morse(keyed_alphabet: &String, message: String) -> Result<String, &'static str> {
        let mut frac_morse = String::new();

        for c in message.to_lowercase().chars() {
            match keyed_alphabet.chars().position(|a| a == c) {
                Some(pos) => {
                    frac_morse.extend(FRAC_MORSE_ALPHABET[pos].chars());
                },
                None => {
                    return Err("Invalid message. Please strip any whitespace or non-alphabetic symbols.")
                }
            }
        }

        Ok(frac_morse)
    }

    /// TODO
    fn decrypt_frac_morse(keyed_alphabet: &String, mut message: String) -> Result<String, &'static str> {
        let mut ciphertext = String::new();

        while message.len() % 3 != 0 {
            message.push('.');
        }

        for trigraph in message.as_bytes().chunks(3) {
            if let Some(pos) = FRAC_MORSE_ALPHABET.iter().position(|&t| t.as_bytes() == trigraph) {
                ciphertext.push(keyed_alphabet.chars().nth(pos).unwrap());
            } else {
                return Err("Unknown fractionated morse trigraph found.")
            }
        }

        Ok(ciphertext)
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

    #[test]
    fn decrypt_test() {
        let message = "cpsujiswhsspg";
        let f = FractionatedMorse::new(String::from("key")).unwrap();
        assert_eq!("attackatdawn", f.decrypt(message).unwrap());
    }

    #[test]
    fn encrypt_mixed_case() {
        let message = "AttackAtDawn";
        let f = FractionatedMorse::new(String::from("OranGE")).unwrap();
        assert_eq!("eptvihtxfttpd", f.encrypt(message).unwrap());
    }

    #[test]
    fn decrypt_mixed_case() {
        let message = "EPtvihtXFttPD";
        let f = FractionatedMorse::new(String::from("OranGE")).unwrap();
        assert_eq!("attackatdawn", f.decrypt(message).unwrap());
    }

    #[test]
    fn encrypt_no_key() {
        let message = "defendtheeastwall";
        let f = FractionatedMorse::new(String::from("")).unwrap();
        assert_eq!("jubgvvhscgtshtppjtcs", f.encrypt(message).unwrap());
    }

    #[test]
    fn encrypt_long_key() {
        let message = "defendtheeastwall";
        let f = FractionatedMorse::new(String::from("nnhhyqzabguuxwdrvvctspefmjoklii")).unwrap();
        assert_eq!("xmhbjjgeybfegfttxfye", f.encrypt(message).unwrap());
    }

    #[test]
    fn exhaustive_encrypt() {
        let message = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        let encrypted = "sbiaqtndfnhhulsailijuicothksekjblurhsbiaqtndfn\
                         hhulsailijuicothksekjblurhujxjejesehbhfhghgdgjn";
        let f = FractionatedMorse::new(String::from("exhaustive")).unwrap();
        assert_eq!(encrypted, f.encrypt(message).unwrap());
    }

    #[test]
    fn bad_key() {
        assert!(FractionatedMorse::new(String::from("bad key")).is_err());
    }

    #[test]
    fn decrypt_bad_message() {
        let message = "badmessagefordecryption";
        let f = FractionatedMorse::new(String::from("")).unwrap();
        assert!(f.decrypt(message).is_err());
    }
}
