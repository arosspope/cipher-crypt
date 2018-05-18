//! The Fractionated Morse cipher builds upon Morse code, a well-known method for encoding text
//! which can then be sent across simple visual or audio channels.
//!
//! The Fractionated Morse cipher does not produce a one-to-one mapping of plaintext characters to
//! ciphertext characters and is therefore slightly more secure than a simple substitution cipher.
//! In addition to this, it allows many non-alphabetic symbols to be encoded.
//!
//!
use common::alphabet::Alphabet;
use common::cipher::Cipher;
use common::{alphabet, keygen, morse};

// The fractionated morse trigraph 'alphabet'. Each sequence represents a letter of the alphabet.
const TRIGRAPH_ALPHABET: [&str; 26] = [
    "...", "..-", "..|", ".-.", ".--", ".-|", ".|.", ".|-", ".||", "-..", "-.-", "-.|", "--.",
    "---", "--|", "-|.", "-|-", "-||", "|..", "|.-", "|.|", "|-.", "|--", "|-|", "||.", "||-",
];

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
    /// Will return `Err` if the key contains non-alphabetic symbols or is empty.
    fn new(key: String) -> Result<FractionatedMorse, &'static str> {
        if key.len() < 1 || !alphabet::STANDARD.is_valid(&key) {
            return Err("Invalid key. Keys cannot contain non-alphabetic symbols.");
        }

        let keyed_alphabet = keygen::keyed_alphabet(&key, alphabet::STANDARD, true)?;
        Ok(FractionatedMorse {
            keyed_alphabet: keyed_alphabet,
        })
    }

    /// Encrypt a message using a Fractionated Morse cipher.
    ///
    /// Morse code supports the characters `a-z`, `A-Z`, `0-9` and the special characters
    /// `@ ( ) . , : ' " ! ? - ; =`. This function will return `Err` if the message contains any
    /// symbols that do not meet this criteria. As morse code does not preserve case, all messages
    /// will be transposed to uppercase automatically.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, FractionatedMorse};
    ///
    /// let fm = FractionatedMorse::new(String::from("key")).unwrap();
    /// assert_eq!("CPSUJISWHSSPFANR", fm.encrypt("AttackAtDawn!").unwrap());
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
        let mut morse = FractionatedMorse::to_morse(message)?;

        //Pad the morse so that it can be interpreted properly as a fractionated message
        FractionatedMorse::pad(&mut morse);
        FractionatedMorse::encrypt_sequence(&self.keyed_alphabet, &morse)
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
    /// assert_eq!("ATTACKATDAWN!", fm.decrypt("cpsujiswhsspfanr").unwrap());
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
        let seq = FractionatedMorse::to_trigraphs(&self.keyed_alphabet, cipher_text)?;
        FractionatedMorse::decrypt_sequence(&seq)
    }
}

impl FractionatedMorse {
    /// Takes a message and converts it to Morse code, using the character `|` as a separator.
    /// The transposed sequence is ended with two separators `||`. This function returns `Err`
    /// if an unsupported symbol is present. The support characters are `a-z`, `A-Z`, `0-9` and
    /// the special characters `@ ( ) . , : ' " ! ? - ; =`.
    fn to_morse(message: &str) -> Result<String, &'static str> {
        let mut morse = String::new();

        // Attempt to convert each letter in message to the corresponding morse sequence.
        for c in message.chars() {
            match morse::encode_character(c) {
                Some(sequence) => {
                    morse.push_str(sequence);
                    morse.push('|');
                }
                None => return Err("Unsupported character detected."),
            }
        }

        morse.push('|'); // Finish the Morse message with a double separator `||`.
        Ok(morse)
    }

    /// Takes a morse sequence and converts it to an alphabetic string using the fractionated
    /// morse method.
    ///
    /// This function returns `Err` if an invalid fractionated morse trigraph is encountered.
    fn encrypt_sequence(key: &str, morse: &str) -> Result<String, &'static str> {
        let mut ciphertext = String::new();

        // Loop over each trigraph and decode it to an alphabetic character
        for trigraph in morse.as_bytes().chunks(3) {
            match TRIGRAPH_ALPHABET
                .iter()
                .position(|&t| t.as_bytes() == trigraph)
            {
                Some(pos) => ciphertext.push(key.chars().nth(pos).unwrap()), //Safe unwrap
                None => return Err("Unknown trigraph sequence within the morse code."),
            }
        }

        Ok(ciphertext)
    }

    /// Takes ciphertext and converts it to a sequence of trigraph symbols.
    ///
    /// return `Err` if a non-alphabetic symbol is present in the message.
    fn to_trigraphs(key: &str, ciphertext: &str) -> Result<String, &'static str> {
        let mut sequence = String::new();

        // We are using an uppercase keyed alphabet, so the message must be also
        for c in ciphertext.to_uppercase().chars() {
            match key.chars().position(|k| k == c) {
                //Find position of char in the keyed alphabet
                Some(pos) => sequence.push_str(TRIGRAPH_ALPHABET[pos]),
                None => return Err("Ciphertext cannot contain non-alphabetic symbols."),
            }
        }

        Ok(sequence)
    }

    /// Takes a sequence of trigraphs, which is then interpreted as morse code so that it may be
    /// converted back to plaintext.This function returns `Err` if an invalid morse character is
    /// encountered.
    fn decrypt_sequence(sequence: &str) -> Result<String, &'static str> {
        let mut plaintext = String::new();
        let mut trigraphs = String::from(sequence);

        // Remove character separators from the beginning of the message if present
        while trigraphs.starts_with('|') {
            trigraphs.remove(0);
        }

        // Loop over every Morse character
        for morse_seq in trigraphs.split('|') {
            // A double separator signifies message end. As we are splitting on '|',
            // the sequence '||' will produce an empty string.
            if morse_seq == "" {
                break;
            }

            // Find the Morse character in the alphabet and decode it.
            match morse::decode_sequence(morse_seq) {
                Some(c) => plaintext.push_str(c),
                None => return Err("Unknown morsecode sequence in trigraphs"),
            }
        }

        Ok(plaintext)
    }

    /// Takes a morse sequence and pads it with dots to a length that is a multiple of 3.
    /// This allows it to be interpreted as a Fractionated Morse message.
    fn pad(morse_sequence: &mut String) {
        while morse_sequence.len() % 3 != 0 {
            morse_sequence.push('.');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_test() {
        let message = "attackatdawn";
        let f = FractionatedMorse::new(String::from("key")).unwrap();
        assert_eq!("CPSUJISWHSSPG", f.encrypt(message).unwrap());
    }

    #[test]
    fn decrypt_test() {
        let message = "cpsujiswhsspg";
        let f = FractionatedMorse::new(String::from("key")).unwrap();
        assert_eq!("ATTACKATDAWN", f.decrypt(message).unwrap());
    }

    #[test]
    fn encrypt_mixed_case() {
        let message = "AttackAtDawn";
        let f = FractionatedMorse::new(String::from("OranGE")).unwrap();
        assert_eq!("EPTVIHTXFTTPD", f.encrypt(message).unwrap());
    }

    #[test]
    fn decrypt_mixed_case() {
        let message = "EPtvihtXFttPD";
        let f = FractionatedMorse::new(String::from("OranGE")).unwrap();
        assert_eq!("ATTACKATDAWN", f.decrypt(message).unwrap());
    }

    #[test]
    fn encrypt_punctuation() {
        let m = "Testingpunctuation!Willitwork?";
        let f = FractionatedMorse::new(String::from("Punctuation")).unwrap();
        assert_eq!(m.to_uppercase(), f.decrypt(&f.encrypt(m).unwrap()).unwrap());
    }

    #[test]
    fn encrypt_no_key() {
        assert!(FractionatedMorse::new(String::from("")).is_err());
    }

    #[test]
    fn encrypt_long_key() {
        let message = "defendtheeastwall";
        let f = FractionatedMorse::new(String::from("nnhhyqzabguuxwdrvvctspefmjoklii")).unwrap();
        assert_eq!("XMHBJJGEYBFEGFTTXFYE", f.encrypt(message).unwrap());
    }

    #[test]
    fn exhaustive_encrypt_decrypt() {
        let m = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.,:\'\"!?@-;()=";
        let f = FractionatedMorse::new(String::from("exhaustive")).unwrap();
        assert_eq!(m.to_uppercase(), f.decrypt(&f.encrypt(m).unwrap()).unwrap());
    }

    #[test]
    fn bad_key() {
        assert!(FractionatedMorse::new(String::from("bad key")).is_err());
    }

    #[test]
    fn encrypt_bad_message() {
        let message = "Spaces are not supported.";
        let f = FractionatedMorse::new(String::from("test")).unwrap();
        assert!(f.encrypt(message).is_err());
    }

    #[test]
    fn decrypt_bad_message() {
        let message = "badmessagefordecryption";
        let f = FractionatedMorse::new(String::from("test")).unwrap();
        assert!(f.decrypt(message).is_err());
    }
}
