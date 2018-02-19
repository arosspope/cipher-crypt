//! The ADFGVX cipher was a field cipher used by the German Army on the Western Front during World
//! War I.
//!
//! ADFGVX was an extension of an earlier cipher called ADFGX. It uses a polybius square and a
//! columnar transposition cipher.
//!
use std::string::String;
use common::cipher::Cipher;
use common::{alphabet, keygen};
use columnar_transposition::ColumnarTransposition;
use Polybius;

const ADFGVX_CHARS: [char; 6] = ['A', 'D', 'F', 'G', 'V', 'X'];

/// This struct is created by the `new()` method. See its documentation for more.
pub struct ADFGVX {
    key: String,
    keyword: String,
    null_char: String,
}

impl Cipher for ADFGVX {
    type Key = (String, String, String);
    type Algorithm = ADFGVX;

    /// Initialise a ADFGVX cipher.
    /// All we are interested in is:
    ///  - The 36 character key that will be stored in the Polybius square
    ///  - The keyword that will be used to transpose the output of the Polybius square function
    ///  - An optional `null_char` that will be used for the `ColumnarTransposition`
    ///
    fn new(key: (String, String, String)) -> Result<ADFGVX, &'static str> {
        // Check the validity of the key
        keygen::keyed_alphabet(&key.0, alphabet::ALPHANUMERIC, false)?;

        Ok(ADFGVX {
            key: key.0,
            keyword: key.1,
            null_char: key.2,
        })
    }

    /// Encrypt a message using a ADFGVX cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, ADFGVX};
    ///
    /// let key = String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8");
    /// let key_word = String::from("GERMAN");
    /// let null_char = String::from("");
    ///
    /// let a = ADFGVX::new((
    ///     key,
    ///     key_word,
    ///     null_char
    /// )).unwrap();
    ///
    /// let cipher_text = concat!(
    ///     "gfxffgxgDFAXDAVGDgxvadaaxxXFDDFGGGFdfaxdavgdVDAGFAXVVxfdd",
    ///     "fgggfVVVAGFFAvvvagffaGXVADAAXXvdagfaxvvGFXFFGXG"
    /// );
    ///
    /// assert_eq!(
    ///     cipher_text,
    ///     a.encrypt("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    ///         .unwrap()
    /// );
    /// ```
    ///
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Can't get around the borrowing here...
        let key = self.key.clone();
        let keyword = self.keyword.clone();
        let null_char = self.null_char.clone();

        // Two steps to encrypt
        //  1. Create a polybius square
        let p = Polybius::new((key.to_string(), ADFGVX_CHARS, ADFGVX_CHARS)).unwrap();
        // Encrypt with this
        let initial_ciphertext = p.encrypt(message).unwrap();
        //  2. Columnar transposition
        let ct = ColumnarTransposition::new((keyword, null_char)).unwrap();
        // Encrypt with this
        let ciphertext = ct.encrypt(&initial_ciphertext).unwrap();

        Ok(ciphertext)
    }

    /// Decrypt a message using a ADFGVX cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, ADFGVX};
    ///
    /// let key = String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8");
    /// let key_word = String::from("GERMAN");
    /// let null_char = String::from("");
    ///
    /// let a = ADFGVX::new((
    ///     key,
    ///     key_word,
    ///     null_char
    /// )).unwrap();
    ///
    /// let cipher_text = concat!(
    ///     "gfxffgxgDFAXDAVGD gxvadaaxxXFDDFGGGFdfaxdav",
    ///     "gdVDAGFAXVVxfddfgggfVVVAGFFA vvvagffaGXVADAAXX vdagfaxvvGFXFFGXG "
    /// );
    ///
    /// assert_eq!(
    ///     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    ///      a.decrypt(cipher_text).unwrap()
    /// );
    /// ```
    ///
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        let key = self.key.clone();
        let keyword = self.keyword.clone();
        let null_char = self.null_char.clone();
        // Two steps to decrypt:
        // 1. Create a ColumnarTransposition and decrypt
        let ct = ColumnarTransposition::new((keyword, null_char)).unwrap();
        let round_one = ct.decrypt(ciphertext).unwrap();
        // 2. Create a Polybius square and decrypt
        let p = Polybius::new((key.to_string(), ADFGVX_CHARS, ADFGVX_CHARS)).unwrap();
        let message = p.decrypt(&round_one).unwrap();

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_message() {
        let a = ADFGVX::new((
            String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8"),
            String::from("GERMAN"),
            String::from(""),
        )).unwrap();

        let cipher_text = concat!(
            "gfxffgxgDFAXDAVGDgxvadaaxxXFDDFGGGFdfaxdavgdVDAGFAX",
            "VVxfddfgggfVVVAGFFAvvvagffaGXVADAAXXvdagfaxvvGFXFFGXG"
        );
        assert_eq!(
            cipher_text,
            a.encrypt("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
                .unwrap()
        );
    }

    #[test]
    fn encrypt_message_with_whitespace_nulls() {
        let a = ADFGVX::new((
            String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8"),
            String::from("GERMAN"),
            String::from(" "),
        )).unwrap();

        // Note: this works as per crate version 0.11.0 - and leaves a trailing
        //       ' ' in the ciphertext.
        let cipher_text = concat!(
            "gfxffgxgDFAXDAVGD gxvadaaxxXFDDFGGGFdfaxdavgdVDAGFAX",
            "VVxfddfgggfVVVAGFFA vvvagffaGXVADAAXX vdagfaxvvGFXFFGXG "
        );
        assert_eq!(
            cipher_text,
            a.encrypt("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
                .unwrap()
        );
    }

    #[test]
    fn decrypt_message() {
        let a = ADFGVX::new((
            String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8"),
            String::from("GERMAN"),
            String::from(""),
        )).unwrap();

        let cipher_text = concat!(
            "gfxffgxgDFAXDAVGDgxvadaaxxXFDDFGGGFdfaxdavgdVDAGFAX",
            "VVxfddfgggfVVVAGFFAvvvagffaGXVADAAXXvdagfaxvvGFXFFGXG"
        );
        assert_eq!(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            a.decrypt(cipher_text).unwrap()
        );
    }

    #[test]
    fn decrypt_message_with_whitespace_nulls() {
        let a = ADFGVX::new((
            String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8"),
            String::from("GERMAN"),
            String::from(" "),
        )).unwrap();

        // Note: this works as per crate version 0.11.0 - and leaves a trailing
        //       ' ' in the ciphertext.
        let cipher_text = concat!(
            "gfxffgxgDFAXDAVGD gxvadaaxxXFDDFGGGFdfaxdavgdVDAGFAX",
            "VVxfddfgggfVVVAGFFA vvvagffaGXVADAAXX vdagfaxvvGFXFFGXG "
        );
        assert_eq!(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            a.decrypt(cipher_text).unwrap()
        );
    }

    #[test]
    fn encrypt_decrypt_message() {
        let a = ADFGVX::new((
            String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8"),
            String::from("VICTORY"),
            String::from(""),
        )).unwrap();

        let plain_text = concat!(
            "We attack at dawn, not later when it is light, ",
            "or at some strange time of the clock. Only at dawn."
        );
        assert_eq!(
            a.decrypt(&a.encrypt(plain_text).unwrap()).unwrap(),
            plain_text
        );
    }

    #[test]
    fn encrypt_decrypt_message_with_nulls() {
        let a = ADFGVX::new((
            String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8"),
            String::from("VICTORY"),
            String::from("\u{0}"),
        )).unwrap();

        let plain_text = concat!(
            "We attack at dawn, not later when it is light, ",
            "or at some strange time of the clock. Only at dawn."
        );
        assert_eq!(
            a.decrypt(&a.encrypt(plain_text).unwrap()).unwrap(),
            plain_text
        );
    }

    #[test]
    fn encrypt_decrypt_message_null_space() {
        let a = ADFGVX::new((
            String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8"),
            String::from("VICTORY"),
            String::from(" "),
        )).unwrap();

        let plain_text = concat!(
            "We attack at dawn, not later when it is light, ",
            "or at some strange time of the clock. Only at dawn."
        );
        assert_eq!(
            a.decrypt(&a.encrypt(plain_text).unwrap()).unwrap(),
            plain_text
        );
    }

    #[test]
    fn with_utf8() {
        let plain_text = "Attack 🗡️ the east wall";
        let a = ADFGVX::new((
            String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8"),
            String::from("GERMAN"),
            String::from(""),
        )).unwrap();

        assert_eq!(
            plain_text,
            a.decrypt(&a.encrypt(plain_text).unwrap()).unwrap()
        );
    }

    #[test]
    fn with_utf8_with_nulls() {
        let plain_text = "Attack 🗡️ the east wall";
        let a = ADFGVX::new((
            String::from("ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8"),
            String::from("GERMAN"),
            String::from("\u{0}"),
        )).unwrap();

        assert_eq!(
            plain_text,
            a.decrypt(&a.encrypt(plain_text).unwrap()).unwrap()
        );
    }

    #[test]
    fn invalid_key_phrase() {
        assert!(
            ADFGVX::new((
                String::from("F@il"),
                String::from("GERMAN"),
                String::from("")
            )).is_err()
        );
    }

}
