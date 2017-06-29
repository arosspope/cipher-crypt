//! Contains helpful constants and functions used in substitution ciphers.
//!
const ALPHABET_LOWER: [char; 26] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

const ALPHABET_UPPER: [char; 26] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];

/// Attempts to find the position of the character in either the lower or upper alphabet.
///
pub fn find_position(c: char) -> Option<usize> {
    ALPHABET_LOWER.iter().position(|&a| a == c)
        .or(ALPHABET_UPPER.iter().position(|&a| a == c))
}

/// Returns a letter from within the alphabet at a specific index
///
/// Will return None if the index is out of bounds
pub fn get_letter(index: usize, is_uppercase: bool) -> Option<char> {
    if index > 25 {
        return None;
    }

    match is_uppercase {
        true => Some(ALPHABET_UPPER[index]),
        false => Some(ALPHABET_LOWER[index])
    }
}
