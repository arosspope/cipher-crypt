//!
use common::alphabet;
use common::cipher::Cipher;
use rulinalg::matrix::Matrix;
use rulinalg::matrix::BaseMatrixMut;
use rulinalg::matrix::BaseMatrix;

/// A Hill cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Hill {
    key: Matrix<f64>, //TODO: determine if its possible to use isize instead
}

impl Cipher for Hill {
    type Key = Matrix<f64>;
    type Algorithm = Hill;

    /// Initialise a Hill cipher given a key matrix.
    ///
    /// Will return `Err` if the matrix is not square or does not have an inverse.
    fn new(key: Matrix<f64>) -> Result<Hill, &'static str> {
        if key.cols() != key.rows() {
            return Err("Key must be a square matrix.")
        }

        if key.clone().inverse().is_err() {
            return Err("The inverse of this matrix cannot be calculated for decryption.")
        }

        Ok(Hill {key: key})
    }

    /// Encrypt a message using a Hill cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        let mut cipher_text = String::new();

        //Only allow chars in the alphabet (no whitespace or symbols)
        for c in message.chars(){
            if alphabet::find_position(c).is_none(){
                return Err("Invalid message. Please strip any whitespace or non-alphabetic symbols.");
            }
        }

        let chunk_size = self.key.rows();
        let mut chunks = message.chars().peekable();

        let mut padding = 0;

        //While
        'outer: while chunks.peek().is_some() {
            let mut buffer: Vec<f64> = Vec::new();

            for n in 0..chunk_size {
                if let Some(c) = chunks.next() {
                    //Push the position of the char in the alphabet to the buffer
                    if let Some(pos) = alphabet::find_position(c) {
                        buffer.push(pos as f64);
                    } else {
                        return Err("Attempted to encrypt a non-alphabetic symbol.");
                    }
                } else {
                    //We need to pad the message
                    padding = chunk_size - buffer.len();
                    for i in 0..padding {
                        buffer.push(0.0);
                    }
                }
            }
            println!("{:?}", buffer);

            //Do some maths and push the result to the cipher text
            let chunks_matrix = Matrix::new(chunk_size, 1, buffer);
            let encrypt_chunks = &self.key * &chunks_matrix;

            for e in encrypt_chunks.iter() {
                if let Some(c) = alphabet::get_letter((e % 26.0).round() as usize, false) {
                    cipher_text.push(c);
                } else {
                    //TODO: something
                }
            }

            if padding > 0 {
                //TODO: Trim off the padding.
                break 'outer;
            }
        }

        Ok(cipher_text)
    }

    /// Decrypt a message using a Caesar cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    fn decrypt(&self, cipher_text: &str) -> Result<String, &'static str> {
        let mut message = String::new();

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt() {
        let h = Hill::new(matrix![  2.0, 4.0, 5.0;
                                    9.0, 2.0, 1.0;
                                    3.0, 17.0, 7.0]).unwrap();
        let s = h.encrypt("ATTACKATDAWNz").unwrap();
        println!("{}", h.encrypt("ATTACKATDAWNz").unwrap());
        //panic!();
    }

    #[test]
    fn valid_key() {
        assert!(Hill::new(matrix![  2.0, 4.0, 5.0;
                                    9.0, 2.0, 1.0;
                                    3.0, 17.0, 7.0]).is_ok());
    }

    #[test]
    fn non_square_matrix(){
        assert!(Hill::new(matrix![  2.0, 4.0;
                                    9.0, 2.0;
                                    3.0, 17.0]).is_err());
    }

    #[test]
    fn non_invertable_matrix(){
        assert!(Hill::new(matrix![  2.0, 2.0, 3.0;
                                    6.0, 6.0, 9.0;
                                    1.0, 4.0, 8.0]).is_err());
    }
}
