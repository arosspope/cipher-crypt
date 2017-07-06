//! The Fractionated Morse cipher builds upon Morse code, a well-known method for encoding text which
//! can then be sent across simple visual or audio channels.
//! 
//! The Fractionated Morse cipher does not produce a one-to-one mapping of plaintext characters to
//! ciphertext characters and is therefore slightly more secure than a simple substitution cipher.
//! In addition to this, it allows many non-alphabetic symbols to be encoded.
use common::cipher::Cipher;
use common::alphabet;
use common::keygen;
use common::morse_alphabet;

// The Fractionated Morse alphabet. Decodings depend on the keyed alphabet
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
            // The key can only contain alphabetic characters.
            if alphabet::find_position(c).is_none() {
                return Err("Invalid key. Fractionated Morse keys cannot contain non-alphabetic symbols.");
            }
        }

        let keyed_alphabet = keygen::keyed_alphabet(&key, false)?;
        Ok(FractionatedMorse { keyed_alphabet: keyed_alphabet })
    }

    /// Encrypt a message using a Fractionated Morse cipher.
    ///
    /// Morse code supports the characters `a-z`, `A-Z`, `0-9` and the special characters
    /// `@ ( ) . , : ' " ! ? - ; =`. This function will return `Err` if the message contains any
    /// symbol not in this list. 
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, FractionatedMorse};
    ///
    /// let fm = FractionatedMorse::new(String::from("key")).unwrap();
    /// assert_eq!("cpsujiswhsspfanr", fm.encrypt("AttackAtDawn!").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Encryption process
        //   (1) The message is encoded in Morse using `|` as a character separator and finishing
        //       with the sequence `||`.
        //   (2) Dots are added to the end of the Morse string until the length is a multiple of 3.
        //   (3) The message is split into groups of 3 and the substitution 0 for '.', 1 for '-'
        //       and 2 for '|' is made to produce a series of ternary numbers between 0 and 26.
        //   (4) The keyed alphabet is obtained from the key.
        //   (5) The numbers obtained in step 3 are converted to letters using the keyed alphabet.
        //   (6) The letters are then concatenated to form the ciphertext.
        // 
        // Example: Key: `alphabet`, Plaintext: `hello`
        //   (1) The Morse message `....|.|.-..|.-..|---||` is produced.
        //   (2) Two dots are added to give `....|.|.-..|.-..|---||..`
        //   (3) ...  -> 000 ->  0
        //       .|.  -> 020 ->  6
        //       |.-  -> 201 -> 19
        //       ..|  -> 002 ->  2
        //       and so on.
        //   (4) The alphabet `alphbetcdfgijkmnoqrsuvwxyz` is produced.
        //   (5) 0(a), 6(t), 19(s), 2(p)
        //   (6) The ciphertext `atsphcmr` is produced.
        let morse = FractionatedMorse::to_morse(message.to_string())?;
        let ciphertext = FractionatedMorse::to_ciphertext(&self.keyed_alphabet, morse)?;
        Ok(ciphertext)
    }

    /// Decrypt a message using a Fractionated Morse cipher.
    ///
    /// The Fractionated Morse alphabet only contains the normal alphabetic characters `a-z`,
    /// therefore this function will return `Err` if the message contains any non-alphabetic
    /// characters. Furthermore, it is possible that a purely alphabetic message will not produce
    /// valid Morse code, in which case an `Err` will again be returned.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, FractionatedMorse};
    ///
    /// let fm = FractionatedMorse::new(String::from("key")).unwrap();
    /// assert_eq!("attackatdawn!", fm.decrypt("cpsujiswhsspfanr").unwrap());
    /// ```
    fn decrypt(&self, cipher_text: &str) -> Result<String, &'static str> {
        // Decryption process:
        //   (1) The keyed alphabet is obtained from the key.
        //   (2) Each ciphertext char is located by index in the keyed alphabet.
        //   (3) The indices are convert to 3 digit ternary and the substitution '.' for 0,
        //       '-' for 1 and '|' for 2 is made to produce a trigraph for each letter.
        //   (4) These trigraphs are substituted for each letter in the message and concatenated
        //       to produce a Morse string.
        //   (5) The Morse message is decoded.
        //
        // Example: Key: `alphabet`, Ciphertext: `atsphcmr`
        //   (1) The alphabet `alphbetcdfgijkmnoqrsuvwxyz` is produced.
        //   (2) a(0), t(6), s(19), p(2), h(3), c(7), m(14), r(18)
        //   (3) 0  -> 000 ->  ...
        //       6  -> 020 ->  .|.
        //       19 -> 201 ->  |.-
        //       2  -> 002 ->  ..|
        //       and so on.
        //   (4) The Morse message `....|.|.-..|.-..|---||..` is produced.
        //   (5) The plaintext `hello i` is recovered.
        let frac_morse = FractionatedMorse::to_fractionated_morse(&self.keyed_alphabet, cipher_text.to_string())?;
        let plaintext = FractionatedMorse::to_plaintext(frac_morse)?;
        Ok(plaintext)
    }
}


impl FractionatedMorse {

    /// Takes a string and tries to convert it to Morse code, using the character `|` as a
    /// separator. The Morse code is ended with two separators `||`. This function returns `Err`
    /// if an unsupported symbol is present. The support characters are `a-z`, `A-Z`, `0-9` and
    /// the special characters `@ ( ) . , : ' " ! ? - ; =`.
    fn to_morse(message: String) -> Result<String, &'static str> {
        let mut morse = String::new();

        // Attempt to convert each letter in message to the corresponding Morse code.
        for c in message.chars() {
            if let Some(m) = morse_alphabet::to_morse(c) {
                morse.extend(m.chars());
                morse.push('|');
            } else {
                return Err("Invalid message. Please strip any whitespace or unsupported symbols.")
            }     
        }

        // Finish the Morse message with a double separator `||`.
        morse.push('|');

        Ok(morse)
    }

    /// Takes a Morse code string, with each Morse character separated by `|`, and converts it to
    /// plaintext. This function returns `Err` if an invalid Morse character is encountered.
    fn to_plaintext(mut morse: String) -> Result<String, &'static str> {
        let mut plaintext = String::new();

        // Remove character separators from the beginning of the message if present
        while morse.starts_with('|') {
            morse.remove(0);
        }

        // Loop over every Morse character
        for morse_chr in morse.split('|') {
            // If a double separator is present we have reached the end of the message therefore we
            // can break. A double separator will produce an empty string when split in the line above.
            if morse_chr == "" {
                break;
            }

            // Find the Morse character in the alphabet and decode it.
            if let Some(c) = morse_alphabet::to_plaintext(morse_chr) {
                plaintext.push(c);
            } else {
                return Err("Invalid Fractionated Morse message. Unknown Morse character found.")
            }
        }

        Ok(plaintext)
    }

    /// Takes a purely alphabetic ciphertext and converts it to Fractionated Morse. This function will
    /// return `Err` if a non-alphabetic symbol is present in the message.
    fn to_fractionated_morse(key: &String, message: String) -> Result<String, &'static str> {
        let mut frac_morse = String::new();

        // We are using a keyed alphabet which is lowercase, therefore loop over a lowercase version
        // of the message.
        for c in message.to_lowercase().chars() {
            if let Some(pos) = key.chars().position(|a| a == c) {
                frac_morse.extend(FRAC_MORSE_ALPHABET[pos].chars());
            } else {
                return Err("Invalid message. Please strip any whitespace or non-alphabetic symbols.")
            }
        }

        Ok(frac_morse)
    }

    /// Takes a Morse string and converts it to a purely alphabetic string using the Fractionated
    /// Morse alphabet. This function returns `Err` if an invalid Fractionated Morse trigraph is
    /// encountered.
    fn to_ciphertext(key: &str, morse: String) -> Result<String, &'static str> {
        let mut ciphertext = String::new();

        // Pad the string so its length is a multiple of 3. This is required to allow the Morse
        // message to be interpreted as a Fractionated Morse message.
        let fractionated_morse = FractionatedMorse::pad_morse_message(morse);

        // Loop over each trigraph and decode it to an alphabetic character
        for trigraph in fractionated_morse.as_bytes().chunks(3) {
            if let Some(pos) = FRAC_MORSE_ALPHABET.iter().position(|&t| t.as_bytes() == trigraph) {
                // FRAC_MORSE_ALPHABET and key both have length 26, therefore this unwrap is safe.
                ciphertext.push(key.chars().nth(pos).unwrap());
            } else {
                // This will only occur for the trigraph `|||` which should not occur in a valid
                // Fractionated Morse message.
                return Err("Unknown Fractionated Morse trigraph found.")
            }
        }

        Ok(ciphertext)
    }

    /// Takes a Morse string and pads it with dots to a length that is a multiple of 3. This allows
    /// it to be interpreted as a Fractionated Morse message.
    fn pad_morse_message(morse: String) -> String {
        let mut fractionated_morse = morse;

        while fractionated_morse.len() % 3 != 0 {
            fractionated_morse.push('.');
        }

        fractionated_morse
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
    fn encrypt_punctuation() {
        let message = "Testingpunctuation!Willitwork?";
        let f = FractionatedMorse::new(String::from("Punctuation")).unwrap();
        assert_eq!("kqoqvwigqlocxurxnhvvekjncidqxtwkfeqgb", f.encrypt(message).unwrap());
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
        let message = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.,:\'\"!?@-;()=";
        let encrypted = "sbiaqtndfnhhulsailijuicothksekjblurhsbiaqtndfnhhulsailijuicot\
                         hksekjblurhujxjejesehbhfhghgdgjacrxlfhufoxiajxbociescaqfqflem";
        let f = FractionatedMorse::new(String::from("exhaustive")).unwrap();
        assert_eq!(encrypted, f.encrypt(message).unwrap());
    }

    #[test]
    fn exhaustive_decrypt() {
        let encrypted = "sbiaqtndfnhhulsailijuicothksekjblurhsbiaqtndfnhhulsailijuicot\
                         hksekjblurhujxjejesehbhfhghgdgjacrxlfhufoxiajxbociescaqfqflem";
        let decrypted = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1234567890.,:\'\"!?@-;()=";
        let f = FractionatedMorse::new(String::from("exhaustive")).unwrap();
        assert_eq!(decrypted, f.decrypt(encrypted).unwrap());
    }

    #[test]
    fn bad_key() {
        assert!(FractionatedMorse::new(String::from("bad key")).is_err());
    }

    #[test]
    fn encrypt_bad_message() {
        let message = "Spaces are not supported.";
        let f = FractionatedMorse::new(String::from("")).unwrap();
        assert!(f.encrypt(message).is_err());
    }

    #[test]
    fn decrypt_bad_message() {
        let message = "badmessagefordecryption";
        let f = FractionatedMorse::new(String::from("")).unwrap();
        assert!(f.decrypt(message).is_err());
    }
}
