//! TODO
use common::cipher::Cipher;
use common::alphabet;
use common::keygen::generate_keyed_alphabet;
use std::ascii::AsciiExt;

// The morse alphabet.
const MORSE_ALPHABET: [(char, &str); 50] = [
    ('a' , ".-"    ), ('b' , "-..."  ), ('c' , "-.-."  ), ('d' , "-.."   ), ('e' , "."     ),
    ('f' , "..-."  ), ('g' , "--."   ), ('h' , "...."  ), ('i' , ".."    ), ('j' , ".---"  ),
    ('k' , "-.-"   ), ('l' , ".-.."  ), ('m' , "--"    ), ('n' , "-."    ), ('o' , "---"   ),
    ('p' , ".--."  ), ('q' , "--.-"  ), ('r' , ".-."   ), ('s' , "..."   ), ('t' , "-"     ),
    ('u' , "..-"   ), ('v' , "...-"  ), ('w' , ".--"   ), ('x' , "-..-"  ), ('y' , "-.--"  ),
    ('z' , "--.."  ), ('1' , ".----" ), ('2' , "..---" ), ('3' , "...--" ), ('4' , "....-" ),
    ('5' , "....." ), ('6' , "-...." ), ('7' , "--..." ), ('8' , "---.." ), ('9' , "----." ),
    ('0' , "-----" ), (' ' , ""      ), ('.' , ".-.-.-"), (',' , "--..--"), (':' , "---..."),
    ('\'', ".----."), ('"', ".-..-." ), ('!' , "-.-.--"), ('?' , "..--.."), ('@' , ".--.-."),
    ('-' , "-....-"), (';' , "-.-.-."), ('(' , "-.--." ), (')' , "-.--.-"), ('=' , "-...-" )];

// The fractionated morse alphabet. Decodings depend on the keyed alphabet
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
            // Keys can only contain characters in the known alphabet.
            // Its used to key the fractionated morse alphabet and therefore cannot contain numbers.
            if alphabet::find_position(c).is_none() {
                return Err("Invalid key. Fractionated Morse keys cannot contain non-alphabetic symbols.");
            }
        }

        let keyed_alphabet = generate_keyed_alphabet(&key, false)?;
        Ok(FractionatedMorse { keyed_alphabet: keyed_alphabet })
    }

    /// Encrypt a message using a Fractionated Morse cipher.
    ///
    /// Morse code only supports alphanumeric characters, therefore this function will reject
    /// with `Err` if the message contains any non-alphanumeric symbols. 
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, FractionatedMorse};
    ///
    /// let fm = FractionatedMorse::new(String::from("key")).unwrap();
    /// assert_eq!("cpsujixpzycbuuiq", fm.encrypt("Attack at dawn!").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Encryption process
        //   (1) The message is encoded in morse using `|` as a character seperator and finishing
        //       with the sequence `||`.
        //   (2) Dots are added to the end of the morse string until the length is a multiple of 3.
        //   (3) The message is split into groups of 3 and the substituion 0 for '.', 1 for '-'
        //       and 2 for '|' is made to produce a series of numbers between 0 and 25.
        //   (4) The keyed alphabet is obtained from the key.
        //   (5) The numbers obtained in step 3 are converted to letters using the keyed alphabet.
        //   (6) The letters are then concatinated to form the ciphertext.
        // 
        // Example: Key: `alphabet`, Plaintext: `hello`
        //   (1) The morse message `....|.|.-..|.-..|---||` is produced.
        //   (2) Two dots are added to give `....|.|.-..|.-..|---||..`
        //   (3) ...  -> 000 ->  0
        //       .|.  -> 020 ->  6
        //       |.-  -> 201 -> 19
        //       ..|  -> 002 ->  2
        //       and so on.
        //   (4) The alphabet `alphbetcdfgijkmnoqrsuvwxyz` is produced.
        //   (5) 0(a), 6(t), 19(s), 2(p)
        //   (6) The ciphertext `atsphcmr` is produced.
        let morse = FractionatedMorse::encrypt_morse(message.to_string())?;
        let ciphertext = FractionatedMorse::decrypt_frac_morse(&self.keyed_alphabet, morse)?;
        Ok(ciphertext)
    }

    /// Decrypt a message using a Fractionated Morse cipher.
    ///
    /// The Fractionated Morse alphabet only contains the normal alphabetic characters a-z,
    /// therefore this function will reject with `Err` if the message contains any non-alphabetic
    /// characters. Furthermore, it is possible that a purely alphabetic message will not produce
    /// valid morse code, in which case an `Err` will be returned.
    ///
    /// An additional `i` or `e` may be present at the end of the decrypted message due to padding
    /// during the encryption process.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, FractionatedMorse};
    ///
    /// let fm = FractionatedMorse::new(String::from("key")).unwrap();
    /// assert_eq!("attack at dawn!", fm.decrypt("cpsujixpzycbuuiq").unwrap());
    /// ```
    fn decrypt(&self, cipher_text: &str) -> Result<String, &'static str> {
        // Decryption process:
        //   (1) The keyed alphabet is obtained from the key.
        //   (2) Each ciphertext char is located by index in the keyed alphabet.
        //   (3) The indices are convert to 3 digit ternary and the substituion '.' for 0,
        //       '-' for 1 and '|' for 2 is made to produce a trigraph for each letter.
        //   (4) These trigraphs then substituted for each letter in the message and concatinated
        //       to produce a morse string.
        //   (5) The morse message is decoded up until the sequence `||`.
        //
        // Example: Key: `alphabet`, Ciphertext: `atsphcmr`
        //   (1) The alphabet `alphbetcdfgijkmnoqrsuvwxyz` is produced.
        //   (2) a(0), t(6), s(19), p(2), h(3), c(7), m(14), r(18)
        //   (3) 0  -> 000 ->  ...
        //       6  -> 020 ->  .|.
        //       19 -> 201 ->  |.-
        //       2  -> 002 ->  ..|
        //       and so on.
        //   (4) The morse message `....|.|.-..|.-..|---||..` is produced.
        //   (5) The plaintext `hello` is recovered.
        let frac_morse = FractionatedMorse::encrypt_frac_morse(&self.keyed_alphabet, cipher_text.to_string())?;
        let plaintext = FractionatedMorse::decrypt_morse(frac_morse)?;
        Ok(plaintext)
    }
}


impl FractionatedMorse {

    /// Takes an alphanumeric string and converts it to morse code, using the character `|` as a
    /// seperator. The morse code is ended with two seperators `||`. This function returns `Err`
    /// if an unsupported symbol is present. The support characters are a-z, A-Z, 0-9, spaces and
    /// the special characters @ ( ) . , : ' " ! ? - ; =
    fn encrypt_morse(message: String) -> Result<String, &'static str> {
        let mut morse = String::new();

        // Convert each letter in message to corresponding morse characters.
        // We cannot have multiple spaces in a row, otherwise the invalid fractionated morse
        // character `|||` will be produced. Therefore, split by whitespace and only add one space
        // in between each word.
        for word in message.split_whitespace() {
            for c in word.chars() {
                if let Some(pos) = MORSE_ALPHABET.iter().position(|m| m.0 == c.to_ascii_lowercase()) {
                    morse.extend(MORSE_ALPHABET[pos].1.chars());
                    morse.push('|');
                } else {
                    return Err("Invalid message. Please strip any unsupported symbols.")
                }
            }
            morse.push('|');
        }

        // Remove the final space and end the message with two seperators
        morse.pop();
        morse.push('|');

        Ok(morse)
    }

    /// Takes a morse code string, with each morse character seperated by `|`, and converts it to
    /// plaintext. Once the end of message marker, `||`, has been found, nothing further is done. 
    /// This function returns `Err` if an invalid morse character is encountered.
    fn decrypt_morse(mut message: String) -> Result<String, &'static str> {
        let mut plaintext = String::new();

        // Remove character seperators from the beginning of the message if present
        while message.starts_with('|') {
            message.remove(0);
        }

        // Loop over every morse character
        for morse_chr in message.split('|') {
            // Find the morse character in the alphabet and decode it.
            if let Some(pos) = MORSE_ALPHABET.iter().position(|&m| m.1 == morse_chr) {
                plaintext.push(MORSE_ALPHABET[pos].0);
            } else {
                return Err("Invalid fractionated morse message. Unknown morse character found.")
            }
        }

        // Messages are ended with `||` but this will be decoded as a two spaces in the loop above.
        // Therefore remove any trailing whitespace. This will also remove any whitespace present
        // at the end of the plaintext.
        plaintext = plaintext.trim_right().to_string();

        Ok(plaintext)
    }

    /// Takes a alphabetic string and converts it to fractionated morse. This function will
    /// return `Err` if a non-alphabetic symbol is present in the message.
    fn encrypt_frac_morse(keyed_alphabet: &String, message: String) -> Result<String, &'static str> {
        let mut frac_morse = String::new();

        // We are using a keyed alphabet which is lowercase, therefore loop over a lowercase version
        // of the message.
        for c in message.to_lowercase().chars() {
            if let Some(pos) = keyed_alphabet.chars().position(|a| a == c) {
                frac_morse.extend(FRAC_MORSE_ALPHABET[pos].chars());
            } else {
                return Err("Invalid message. Please strip any whitespace or non-alphabetic symbols.")
            }
        }

        Ok(frac_morse)
    }

    /// Takes a morse string, pads it with dots to a length that is a multiple of 3, and converts
    /// it to an alphabetic string. This function returns `Err` if an invalid fractionated morse
    /// character is encountered.
    fn decrypt_frac_morse(keyed_alphabet: &String, mut message: String) -> Result<String, &'static str> {
        let mut ciphertext = String::new();

        // Trigraphs are required, so pad the message with dots until the length is a multiple of 3.
        while message.len() % 3 != 0 {
            message.push('.');
        }

        // Loop over each trigraph and decode it to an alphabetic character
        for trigraph in message.as_bytes().chunks(3) {
            if let Some(pos) = FRAC_MORSE_ALPHABET.iter().position(|&t| t.as_bytes() == trigraph) {
                // FRAC_MORSE_ALPHABET and keyed_alphabet both have length 26, therefore this unwrap
                // is safe.
                ciphertext.push(keyed_alphabet.chars().nth(pos).unwrap());
            } else {
                // This will only occur for the trigraph `|||` which should not occur in a valid
                // fractionated morse message.
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
    fn encrypt_punctuation() {
        let message = "Testing  punctuation!   Will it work?";
        let f = FractionatedMorse::new(String::from("Punctuation")).unwrap();
        assert_eq!("kqoqvwbtiafeoqklqwlocjrkidrnqxrljcvktnq", f.encrypt(message).unwrap());
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
        let message = "abcdefghijklmnopqrstuvwxyz1234567890 .,:\'\"!?@-;()=";
        let encrypted = "sbiaqtndfnhhulsailijuicothksekjblurhujxjejes\
                         ehbhfhghgdgjoalbjgeogtbdcunftfdbxqciuiusbsn";
        let f = FractionatedMorse::new(String::from("exhaustive")).unwrap();
        assert_eq!(encrypted, f.encrypt(message).unwrap());
    }

    #[test]
    fn exhaustive_decrypt() {
        let message = "abcdefghijklmnopqrstuvwxyz1234567890 .,:\'\"!?@-;()= i";
        let encrypted = "sbiaqtndfnhhulsailijuicothksekjblurhujxjejes\
                         ehbhfhghgdgjoalbjgeogtbdcunftfdbxqciuiusbsn";
        let f = FractionatedMorse::new(String::from("exhaustive")).unwrap();
        assert_eq!(message, f.decrypt(encrypted).unwrap());
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
