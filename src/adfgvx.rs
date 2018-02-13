//! The ADFGVX cipher was a field cipher used by the German Army on the Western Front during World War I.
//! ADFGVX was an extension of an earlier cipher called ADFGX.
//! It uses a polybius square and a columnar transposition
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
}

impl Cipher for ADFGVX {
    type Key = (String, String);
    type Algorithm = ADFGVX;

    /// Initialise a ADFGVX cipher.
    /// All we are interested in is:
    ///  - The 36 character key that will be stored in the Polybius square
    ///  - The keyword that will be used to transpose the output of the Polybius square function
    ///
    fn new(key: (String, String)) -> Result<ADFGVX, &'static str> {
        // Check the validity of the key
        keygen::keyed_alphabet(&key.0, alphabet::ALPHANUMERIC, false)?;
        Ok(ADFGVX {
            key: key.0,
            keyword: key.1,
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
    /// let a = ADFGVX::new((
    ///     "ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8".to_string(),
    ///     "GERMAN".to_string(),
    /// )).unwrap();

    /// let cipher_text = concat!(
    ///     "GFXFFGXGDFAXDAVGD GXVADAAXXXFDDFGGGFDFAXD",
    ///     "AVGDVDAGFAXVVXFDDFGGGFVVVAGFFA VVVAGFFAGXVADAAXX VDAGFAXVVGFXFFGXG "
    /// );
    /// assert_eq!(
    ///     cipher_text,
    ///     a.encrypt("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    ///         .unwrap()
    ///         .to_uppercase()
    /// );
    /// ```
    ///
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        // Can't get around the borrowing here...
        let key = self.key.clone();
        let keyword = self.keyword.clone();

        // Two steps to encrypt
        //  1. Create a polybius square
        let p = Polybius::new((key.to_string(), ADFGVX_CHARS, ADFGVX_CHARS)).unwrap();
        // Encrypt with this
        let initial_ciphertext = p.encrypt(message).unwrap();
        //  2. Columnar transposition
        let ct = ColumnarTransposition::new(keyword).unwrap();
        // Encrypt with this
        // TODO: Issue is that it is adding in spurious ' ' white space chars...
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
    /// let a = ADFGVX::new((
    ///        "ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8".to_string(),
    ///        "GERMAN".to_string(),
    ///    )).unwrap();
    ///
    /// let cipher_text =
    ///             concat!(
    ///               "gfxffgxgDFAXDAVGD gxvadaaxxXFDDFGGGFdfaxdav",
    ///               "gdVDAGFAXVVxfddfgggfVVVAGFFA vvvagffaGXVADAAXX vdagfaxvvGFXFFGXG ");
    /// assert_eq!(
    ///     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    ///      a.decrypt(cipher_text).unwrap()
    ///    );
    /// ```
    ///
    fn decrypt(&self, ciphertext: &str) -> Result<String, &'static str> {
        let key = self.key.clone();
        let keyword = self.keyword.clone();

        // Two steps to decrypt:
        // 1. Create a ColumnarTransposition and decrypt
        let ct = ColumnarTransposition::new(keyword).unwrap();
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
        //     A D F G V X
        //  A| p h 0 q g 6
        //  D| 4 m e a 1 y
        //  F| l 2 n o f d
        //  G| x k r 3 c v
        //  V| s 5 z w 7 b
        //  X| j 9 u t i 8
        let a = ADFGVX::new((
            "ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8".to_string(),
            "GERMAN".to_string(),
        )).unwrap();

        let cipher_text = concat!(
            "gfxffgxgDFAXDAVGD gxvadaaxxXFDDFGGGFdfaxdav",
            "gdVDAGFAXVVxfddfgggfVVVAGFFA vvvagffaGXVADAAXX vdagfaxvvGFXFFGXG "
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
            "ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8".to_string(),
            "GERMAN".to_string(),
        )).unwrap();

        let cipher_text = concat!(
            "gfxffgxgDFAXDAVGD gxvadaaxxXFDDFGGGFdfaxdav",
            "gdVDAGFAXVVxfddfgggfVVVAGFFA vvvagffaGXVADAAXX vdagfaxvvGFXFFGXG "
        );
        assert_eq!(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            a.decrypt(cipher_text).unwrap()
        );
    }

    #[test]
    fn with_utf8() {
        let m = "Attack 🗡️ the east wall";
        let a = ADFGVX::new((
            "ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8".to_string(),
            "GERMAN".to_string(),
        )).unwrap();

        assert_eq!(m, a.decrypt(&a.encrypt(m).unwrap()).unwrap());
    }

    #[test]
    fn invalid_key_phrase() {
        assert!(ADFGVX::new(("F@il".to_string(), "GERMAN".to_string())).is_err());
    }

}
