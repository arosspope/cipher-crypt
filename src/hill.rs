//!
use common::cipher::Cipher;
use rulinalg::matrix::Matrix;
use rulinalg::matrix::BaseMatrixMut;
use rulinalg::matrix::BaseMatrix;

/// A Hill cipher.
///
/// This struct is created by the `new()` method. See its documentation for more.
pub struct Hill {
    key: Matrix<f64>,
}

impl Cipher for Hill {
    type Key = Matrix<f64>;
    type Algorithm = Hill;

    /// Initialise a Hill cipher given a square matrix.
    ///
    fn new(key: Matrix<f64>) -> Result<Hill, &'static str> {
        if key.cols() == key.rows() {
            return Ok(Hill {key: key});
        }

        //Todo: additional gcd check (gcd(i, 26) == 1)
        Err("Key must be a perfect square.")
    }

    /// Encrypt a message using a Hill cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    fn encrypt(&self, message: &str) -> String {
        String::from("TODO")
    }

    /// Decrypt a message using a Caesar cipher.
    ///
    /// # Examples
    /// Basic usage:
    ///
    fn decrypt(&self, cipher_text: &str) -> String {
        String::from("TODO")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
