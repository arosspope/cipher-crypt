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

/// Performs a modulo on an index so that its value references a position within the alphabet. This
/// function handles negative wrap around modulo as rust does not natievly support it.
///
pub fn modulo(i: isize) -> usize {
    (((i % 26) + 26) % 26) as usize
}

/// Will check if the text contains alphabetic symbols only.
///
pub fn is_alphabetic_only(text: &str) -> bool {
    for c in text.chars() {
        if find_position(c).is_none(){
            return false;
        }
    }

    true
}

/// Will scrub non-alphabetic characters from the text and return the scrubed version
///
pub fn scrub_text(text: &str) -> String {
    text.chars().into_iter()
        .filter(|&c| find_position(c).is_some()).collect()
}

/// Finds the multiplicative inverse of a number such that `a*x = 1 (mod 26)`. Where `a`
/// is the number we are inverting, and `x` is the multiplicative inverse.
///
pub fn multiplicative_inverse(a: isize) -> Option<usize> {
    for x in 1..26 {
        if modulo((a * x) as isize) == 1 {
            return Some(x as usize);
        }
    }

    None
}
