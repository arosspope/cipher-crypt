//! Contains helpful constants and functions used in Morse-based ciphers.
//!

// The Morse alphabet.
// Obtained from https://morsecode.scphillips.com/morse2.html
const MORSE_ALPHABET: [(char, &str); 75] = [
    ('a' , ".-"    ), ('b' , "-..."  ), ('c' , "-.-."  ), ('d' , "-.."   ), ('e' , "."     ),
    ('f' , "..-."  ), ('g' , "--."   ), ('h' , "...."  ), ('i' , ".."    ), ('j' , ".---"  ),
    ('k' , "-.-"   ), ('l' , ".-.."  ), ('m' , "--"    ), ('n' , "-."    ), ('o' , "---"   ),
    ('p' , ".--."  ), ('q' , "--.-"  ), ('r' , ".-."   ), ('s' , "..."   ), ('t' , "-"     ),
    ('u' , "..-"   ), ('v' , "...-"  ), ('w' , ".--"   ), ('x' , "-..-"  ), ('y' , "-.--"  ),
    ('z' , "--.."  ),
    ('A' , ".-"    ), ('B' , "-..."  ), ('C' , "-.-."  ), ('D' , "-.."   ), ('E' , "."     ),
    ('F' , "..-."  ), ('G' , "--."   ), ('H' , "...."  ), ('I' , ".."    ), ('J' , ".---"  ),
    ('K' , "-.-"   ), ('L' , ".-.."  ), ('M' , "--"    ), ('N' , "-."    ), ('O' , "---"   ),
    ('P' , ".--."  ), ('Q' , "--.-"  ), ('R' , ".-."   ), ('S' , "..."   ), ('T' , "-"     ),
    ('U' , "..-"   ), ('V' , "...-"  ), ('W' , ".--"   ), ('X' , "-..-"  ), ('Y' , "-.--"  ),
    ('Z' , "--.."  ),
    ('1' , ".----" ), ('2' , "..---" ), ('3' , "...--" ), ('4' , "....-" ), ('5' , "....." ),
    ('6' , "-...." ), ('7' , "--..." ), ('8' , "---.." ), ('9' , "----." ), ('0' , "-----" ),
    ('.' , ".-.-.-"), (',' , "--..--"), (':' , "---..."), ('\'', ".----."), ('"', ".-..-." ),
    ('!' , "-.-.--"), ('?' , "..--.."), ('@' , ".--.-."), ('-' , "-....-"), (';' , "-.-.-."),
    ('(' , "-.--." ), (')' , "-.--.-"), ('=' , "-...-" )
];


/// Attempts to convert a given single Morse character into a plaintext character
///
/// Will return None if the Morse code isn't present in the alphabet
pub fn to_plaintext(m: &str) -> Option<char> {
	if let Some(index) = MORSE_ALPHABET.iter().position(|&a| a.1 == m) {
		if let Some(entry) = MORSE_ALPHABET.get(index) {
			return Some(entry.0)
		}
	}

	None
}

/// Attempts to convert the character given into Morse code
///
/// Will return None if the character isn't present in the alphabet
pub fn to_morse(c: char) -> Option<&'static str> {
	if let Some(index) = MORSE_ALPHABET.iter().position(|&a| a.0 == c) {
		if let Some(entry) = MORSE_ALPHABET.get(index) {
			return Some(entry.1)
		}
	} 

	None
}