//! Contains helpful constants and functions used in substitution ciphers.
//!
const ALPHABET_LOWER: [char; 26] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

const ALPHABET_UPPER: [char; 26] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];

const ALPHANUMERIC_LOWER: [char; 36] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3',
'4', '5', '6', '7', '8', '9', '0'];

const ALPHANUMERIC_UPPER: [char; 36] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3',
'4', '5', '6', '7', '8', '9', '0'];

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

/// Attempts to find the position of the character in lower and upper case alphanumeric alphabets.
///
pub fn find_alphanumeric_position(c: char) -> Option<usize> {
    ALPHANUMERIC_LOWER.iter().position(|&a| a == c)
        .or(ALPHANUMERIC_UPPER.iter().position(|&a| a == c))
}

/// Returns a letter from within the alphanumeric alphabet at a specific index
///
/// Will return None if the index is out of bounds
pub fn get_alphanumeric_symbol(index: usize, is_uppercase: bool) -> Option<char> {
    if index > 35 {
        return None;
    }

    match is_uppercase {
        true => Some(ALPHANUMERIC_UPPER[index]),
        false => Some(ALPHANUMERIC_LOWER[index])
    }
}