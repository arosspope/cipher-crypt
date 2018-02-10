//! The ADFGVX cipher was a field cipher used by the German Army on the Western Front during World War I. 
//! ADFGVX was an extension of an earlier cipher called ADFGX.
//! It uses a polybius square and a columnar transposition
//!
use common::cipher::Cipher;
use columnar_transposition::ColumnarTransposition;
use polybius::Polybius;

/// This struct is created by the `new()` method. See its documentation for more.
pub struct ADFGVX {
    square: HashMap<String, char>,
}

impl Cipher for ADFGVX {
    type Key = (String, [char; 6], [char; 6]);
    type Algorithm = ADFGVX;
}

#[cfg(test)]
mod tests {
    use super::*;
}
