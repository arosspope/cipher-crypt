use std::iter;
use common::alphabet::ALPHABET;

pub struct Vigenere {
    key: String,
}

impl Vigenere {
    pub fn new(key: String) -> Result<Vigenere, &'static str> {
        for c in key.chars() {
            //Keys can only contain characters in the known alphabet
            if ALPHABET.iter().find(|&&a| a == c).is_none() {
                return Err("Invalid key. Vigenere keys cannot contain non-alphabetic symbols.");
            }
        }

        Ok(Vigenere { key: key })
    }

    pub fn encrypt(&self, message: &str) -> String {
        /*  Encryption of a letter in a message:
                    Ci = Ek(Mi) = (Mi + Ki) mod 26
            Where;  Mi = position within the alphabet of ith char in message
                    Ki = position within the alphabet of ith char in key
        */
        let e_key = self.fit_key(message.len());

        Vigenere::poly_substitute(message, e_key, |mi, ki| (mi + ki) % 26)
    }

    pub fn decrypt(&self, cipher_text: &str) -> String {
        /*  Decryption of a letter in a message:
                    Mi = Dk(Ci) = (Ci - Ki) mod 26
            Where;  Ci = position within the alphabet of ith char in cipher text
                    Ki = position within the alphabet of ith char in key
        */
        let d_key = self.fit_key(cipher_text.len());

        let decrypt = |ci, ki| {
            let a: isize = ci as isize - ki as isize;
            (((a % 26) + 26) % 26) as usize
            //Rust does not natievly support negative wrap around modulo operations
        };

        Vigenere::poly_substitute(cipher_text, d_key, decrypt)
    }

    fn fit_key(&self, msg_length: usize) -> String {
        let key_copy = self.key.clone();

        if key_copy.len() >= msg_length {
            return key_copy; //The key is large enough for the message already
        }

        //Repeat the key until it fits within the length of the message
        let mut repeated_key = iter::repeat(key_copy).take((msg_length / self.key.len()) + 1)
            .collect::<String>();

        repeated_key.truncate(msg_length);
        repeated_key
    }

    fn poly_substitute<F>(text: &str, key: String, calc_index: F) -> String
        where F: Fn(usize, usize) -> usize
    {
        let mut s_text = String::new();

        for (i, c) in text.chars().enumerate() {
            //Find the index of the character in the alphabet
            let idx = ALPHABET.iter().position(|&x| x == c);
            match idx {
                Some(ti) => {
                    //Find the index of the key in the alphabet at this position
                    let ki = ALPHABET.iter()
                        .position(|&x| x == key.chars().nth(i).unwrap()).unwrap();

                    //Calculate the index of the substitute char
                    let mut si = calc_index(ti, ki);

                    //If the original character was uppercase we should offset our substitute index
                    //by 26 to reference the upper-half (UPPERCASE) section of the alphabet array
                    if c.is_uppercase() && si < 26 {
                        si += 26;
                    }

                    s_text.push(ALPHABET[si]);
                },
                None => s_text.push(c), //Push non-alphabetic chars 'as-is'
            }
        }

        s_text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_test() {
        let message = "attackatdawn";
        let v = Vigenere::new(String::from("lemon")).unwrap();
        assert_eq!("lxfopvefrnhr", v.encrypt(message));
    }

    #[test]
    fn decrypt_test() {
        let cipher_text = "lxfopvefrnhr";
        let v = Vigenere::new(String::from("lemon")).unwrap();
        assert_eq!("attackatdawn", v.decrypt(cipher_text));
    }

    #[test]
    fn mixed_case() {
        let message = "Attack at Dawn!";
        let v = Vigenere::new(String::from("giovan")).unwrap();

        let cipher_text = v.encrypt(message);
        let plain_text = v.decrypt(&cipher_text);

        assert_eq!(plain_text, message);
    }

    #[test]
    fn with_emoji(){
        let v = Vigenere::new(String::from("emojisarefun")).unwrap();
        let message = "Peace, Freedom and Liberty! 🗡️";
        let encrypted = v.encrypt(message);
        let decrypted = v.decrypt(&encrypted);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn fit_smaller_key() {
        let message = "We are under seige!"; //19 character message
        let v = Vigenere::new(String::from("lemon")).unwrap(); //key length of 5

        assert_eq!("lemonlemonlemonlemo", v.fit_key(message.len()));
        assert!(v.fit_key(message.len()).len() >= message.len());
    }

    #[test]
    fn fit_larger_key() {
        let message = "hi";
        let v = Vigenere::new(String::from("lemon")).unwrap();

        assert_eq!("lemon", v.fit_key(message.len()));
        assert!(v.fit_key(message.len()).len() >= message.len());
    }

    #[test]
    fn mixed_key_case(){
        assert!(Vigenere::new(String::from("LeMoN")).is_ok());
    }

    #[test]
    fn valid_key() {
        assert!(Vigenere::new(String::from("Lemon")).is_ok());
    }

    #[test]
    fn key_with_symbols() {
        assert!(Vigenere::new(String::from("!em@n")).is_err());
    }

    #[test]
    fn key_with_whitespace() {
        assert!(Vigenere::new(String::from("wow this key is a real lemon")).is_err());
    }
}
