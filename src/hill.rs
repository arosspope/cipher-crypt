//!
use common::alphabet;
use common::cipher::Cipher;
use num::integer::gcd;
use rulinalg::matrix::{Matrix, BaseMatrix, BaseMatrixMut};

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

        if gcd(key.clone().det() as isize, 26) != 1 {
            return Err("The inverse determinant of the key cannot be calculated.");
        }

        Ok(Hill {key: key})
    }

    /// Encrypt a message using a Hill cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    fn encrypt(&self, message: &str) -> Result<String, &'static str> {
        Hill::transform_message(&self.key, message)
    }



    /// Decrypt a message using a Caesar cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    fn decrypt(&self, cipher_text: &str) -> Result<String, &'static str> {
        let inverse_key = Hill::calc_inverse_key(self.key.clone())?;

        Hill::transform_message(&inverse_key, cipher_text)
    }
}

impl Hill {
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

        let mut padding = 0;
        if buffer.len() % chunk_size > 0 {
            padding = chunk_size - (buffer.len() % chunk_size);
            for i in 0..padding {
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

        //Return the transformed message ensuring to trim any padding
        Ok (transformed_message[0..(transformed_message.len() - padding)].to_string())
        //Ok(transformed_message)
    }

    fn transform_chunk(key: &Matrix<f64>, chunk: &str)
        -> Result<String, &'static str>
    {
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
    fn transformation(){
        let m = matrix![2.0, 4.0, 5.0;
                        9.0, 2.0, 1.0;
                        3.0, 17.0, 7.0];

        //assert_eq!("PFO", Hill::transform_chunk(m.clone(), "ATT").unwrap());
        //assert_eq!("ATT", Hill::transform_chunk(Hill::calc_inverse_key(m), "PFO").unwrap());
    }

    #[test]
    fn encrypt_no_padding_req() {
        let h = Hill::new(matrix![  2.0, 4.0, 5.0;
                                    9.0, 2.0, 1.0;
                                    3.0, 17.0, 7.0]).unwrap();

        let m = "ATTACKATDAWN";
        assert_eq!(m, h.decrypt(&h.encrypt(m).unwrap()).unwrap());
    }

    #[test]
    fn encrypt_padding_req() {
        let h = Hill::new(matrix![  2.0, 4.0, 5.0;
                                    9.0, 2.0, 1.0;
                                    3.0, 17.0, 7.0]).unwrap();
        let m = "ATTACKATDAWNz";
        assert_eq!(m, h.decrypt(&h.encrypt(m).unwrap()).unwrap());
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
