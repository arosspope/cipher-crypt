//!
use common::alphabet;
use common::cipher::Cipher;
use num::integer::gcd;
use rulinalg::matrix::{Matrix, BaseMatrix, BaseMatrixMut};

/// A Hill cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Hill {
    key: Matrix<isize>,
}

impl Cipher for Hill {
    type Key = Matrix<isize>;
    type Algorithm = Hill;

    /// Initialise a Hill cipher given a key matrix.
    ///
    /// Will return `Err` if one of the following conditions is detected:
    ///
    /// * The `key` matrix is not a square
    /// * The `key` matrix is non-invertable
    /// * The inverse determinant of the `key` matrix cannot be calculated such that
    /// `d*d^-1 == 1 mod 26`
    ///
    /// # Examples
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Hill, Matrix};
    ///
    /// //Initialise a Hill cipher from a 3 x 3 matrix
    /// let m = Matrix::new(3, 3, vec![2, 4, 5, 9, 2, 1, 3, 17, 7]);
    /// let h = Hill::new(m).unwrap();
    /// ```
    fn new(key: Matrix<isize>) -> Result<Hill, &'static str> {
        if key.cols() != key.rows() {
            return Err("Key must be a square matrix.")
        }

        //We want to restrict the caller to supplying Matricies of type isize
        //However, the majority of the matrix operations will be done with type f64
        let m: Matrix<f64> = key.clone().try_into()
            .expect("Could not convert Matrix of type `isize` to `f64`.");

        if m.clone().inverse().is_err() {
            return Err("The inverse of this matrix cannot be calculated for decryption.")
        }

        if gcd(m.clone().det() as isize, 26) != 1 {
            return Err("The inverse determinant of the key cannot be calculated.");
        }

        Ok(Hill {key: key})
    }

    /// Encrypt a message using a Hill cipher.
    ///
    /// It is expected that this message contains alphabetic characters only. Due to the nature of
    /// the hill cipher it is very difficult to transpose whitespace or symbols during the
    /// encryption process. It will reject with `Err` if the message contains any non-alphabetic
    /// symbols.
    ///
    /// You may also notice that your encrypted message is longer than the original. This will
    /// occur when the length of the message is not a multiple of the key matrix size. To
    /// accomodate for this potential difference, the algorithm will add `n` amount of padding
    /// characters so that encryption can occur. It is important that these extra padding
    /// characters are not removed till *after* the decyption process, otherwise the message will
    /// not be transposed properly.
    ///
    /// # Example
    /// Basic usage:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Hill, Matrix};
    ///
    /// let h = Hill::new(Matrix::new(3, 3, vec![2, 4, 5, 9, 2, 1, 3, 17, 7])).unwrap();
    ///
    /// //Padding characters are added during the encryption process
    /// assert_eq!("PFOGOAUCIMpf", h.encrypt("ATTACKEAST").unwrap());
    /// ```
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        Hill::transform_message(&self.key.clone().try_into().unwrap(), message)
    }

    /// Decrypt a message using a Hill cipher.
    ///
    /// It is expected that this message contains alphabetic characters only. Due to the nature of
    /// the hill cipher it is very difficult to transpose whitespace or symbols during the
    /// encryption process. It will reject with `Err` if the message contains any non-alphabetic
    /// symbols.
    ///
    /// You may also notice that your encrypted message is longer than the original. This will
    /// occur when the length of the message is not a multiple of the key matrix size. See encrypt
    /// function for more information.
    ///
    /// # Examples
    /// Example with stripping out padding:
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Hill, Matrix};
    ///
    /// let m = "ATTACKEAST";
    /// let h = Hill::new(Matrix::new(3, 3, vec![2, 4, 5, 9, 2, 1, 3, 17, 7])).unwrap();
    ///
    /// let c = h.encrypt(m).unwrap();
    /// let padding = c.len() - m.len();
    ///
    /// let p = h.decrypt(&c).unwrap();
    /// assert_eq!(m, p[0..(p.len() - padding)].to_string());
    /// ```
    fn decrypt(&self, cipher_text: &str) -> Result<String, &'static str> {
        let inverse_key = Hill::calc_inverse_key(self.key.clone().try_into().unwrap())?;

        Hill::transform_message(&inverse_key, cipher_text)
    }
}

impl Hill {
    /// Initialise a Hill cipher given a phrase.
    ///
    /// The position of each character within the alphabet is used to construct the
    /// Matrix key of the cipher. The variable `chunk_size` defines how many chars (or chunks)
    /// of a message will be transposed during encryption/decryption.
    ///
    /// Will return `Err` if one of the following conditions is detected:
    ///
    /// * The `chunk_size` is less than 2
    /// * The square of `chunk_size` is not equal to the phrase length
    /// * The phrase contains non-alphabetic symbols
    /// * Any of the Err conditions as stipulated by the `new()` fn
    ///
    /// # Example
    ///
    /// ```
    /// use cipher_crypt::{Cipher, Hill};
    ///
    /// let h = Hill::from_phrase("hill", 2).unwrap();
    /// h.encrypt("thing");
    /// ```
    pub fn from_phrase(phrase: &str, chunk_size: usize) -> Result<Hill, &'static str> {
        if chunk_size < 2 {
            return Err("The chunk size must be greater than 1.");
        }

        if chunk_size * chunk_size != phrase.len() {
            return Err("The square of the chunk size must equal the length of the phrase.");
        }

        let mut matrix: Vec<isize> = Vec::new();
        for c in phrase.chars(){
            match alphabet::find_position(c) {
                Some(pos) => matrix.push(pos as isize),
                None => return Err("Phrase cannot contain non-alphabetic symbols."),
            }
        }

        let key = Matrix::new(chunk_size, chunk_size, matrix);
        Hill::new(key)
    }

    /// Core logic of the hill cipher. Transposing messages with matricies
    ///
    fn transform_message(key: &Matrix<f64>, message: &str) -> Result<String, &'static str> {
        //Only allow chars in the alphabet (no whitespace or symbols)
        for c in message.chars(){
            if alphabet::find_position(c).is_none(){
                return Err("Invalid message. Please strip any whitespace or non-alphabetic symbols.");
            }
        }

        let mut transformed_message = String::new();
        let mut buffer = message.to_string();
        let chunk_size = key.rows();

        if buffer.len() % chunk_size > 0 {
            let padding = chunk_size - (buffer.len() % chunk_size);
            for _ in 0..padding {
                buffer.push('a'); //Ensure that the buffer is a multiple of the chunk size
            }
        }

        let mut i = 0;
        while i < buffer.len() {
            match Hill::transform_chunk(&key, &buffer[i..(i+chunk_size)]) {
                Ok(s) => transformed_message.push_str(&s),
                Err(e) => return Err(e),
            }

            i += chunk_size;
        }

        //Return the transformed message - this may have extra padding appended
        Ok(transformed_message)
    }

    /// Transforming a chunk of the message, whose length is deterimend by the size of the matrix
    ///
    fn transform_chunk(key: &Matrix<f64>, chunk: &str) -> Result<String, &'static str> {
        let mut transformed = String::new();

        if key.rows() != chunk.len() {
            return Err("Cannot perform transformation on unequal vector lengths");
        }

        let mut index_representation: Vec<f64> = Vec::new();
        for c in chunk.chars() {
            index_representation.push(
                alphabet::find_position(c)
                .expect("Attempted transformation of non-alphabetic symbol") as f64
            );
        }

        let mut product = key * Matrix::new(index_representation.len(), 1, index_representation);
        product = product.apply(&|x| (x % 26.0).round());

        for (i, pos) in product.iter().enumerate() {
            let orig = chunk.chars().nth(i).expect("Expected to find char at index.");

            transformed.push(
                alphabet::get_letter(*pos as usize, orig.is_uppercase())
                .expect("Calculate index is invalid.")
            );
        }

        Ok (transformed)
    }

    /// Calculates the inverse key for decryption
    ///
    fn calc_inverse_key(key: Matrix<f64>) -> Result<Matrix<f64>, &'static str> {
        let det = key.clone().det();

        //Find the inverse determinant such that: d*d^-1 = 1 mod 26
        let mut det_inverse: Option<isize> = None;
        for i in 1..26 {
            if (det as isize * i ) % 26 == 1 {
                det_inverse = Some(i);
                break;
            }
        }

        //Calucalte the inverse key matrix
        Ok ( key.inverse().unwrap().apply(&|x| {
            let z = (x * det as f64).round();
            let w = ((z % 26.0) + 26.0) % 26.0;
            (w * det_inverse.expect("Inverse for determinant could not be found.") as f64) % 26.0
        }))
    }


}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_from_phrase(){
        assert!(Hill::from_phrase("hill", 2).is_ok());
    }

    #[test]
    fn invalid_phrase(){
        assert!(Hill::from_phrase("killer", 2).is_err());
    }

    #[test]
    fn encrypt_no_padding_req() {
        let h = Hill::new(matrix![  2, 4, 5;
                                    9, 2, 1;
                                    3, 17, 7]).unwrap();

        let m = "ATTACKATDAWN";
        assert_eq!(m, h.decrypt(&h.encrypt(m).unwrap()).unwrap());
    }

    #[test]
    fn encrypt_padding_req() {
        let h = Hill::new(matrix![  2, 4, 5;
                                    9, 2, 1;
                                    3, 17, 7]).unwrap();
        let m = "ATTACKATDAWNz";

        let e = h.encrypt(m).unwrap();
        assert_eq!("PFOGOANPGXFXyrx", e);

        let d = h.decrypt(&e).unwrap();
        assert_eq!("ATTACKATDAWNzaa", d);
    }

    #[test]
    fn valid_key() {
        assert!(Hill::new(matrix![  2, 4, 5;
                                    9, 2, 1;
                                    3, 17, 7]).is_ok());
    }

    #[test]
    fn non_square_matrix(){
        assert!(Hill::new(matrix![  2, 4;
                                    9, 2;
                                    3, 17]).is_err());
    }

    #[test]
    fn non_invertable_matrix(){
        assert!(Hill::new(matrix![  2, 2, 3;
                                    6, 6, 9;
                                    1, 4, 8]).is_err());
    }
}
