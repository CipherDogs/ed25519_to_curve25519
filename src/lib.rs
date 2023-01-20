#![no_std]
#![allow(clippy::all)]
mod field;
mod field_element_2625;
mod sha512;

use field::FieldElement;

// Convert ed25519 public key to curve25519
#[allow(non_snake_case)]
pub fn ed25519_pk_to_curve25519(pk: [u8; 32]) -> [u8; 32] {
    let AY = FieldElement::from_bytes(&pk);

    let mut one_minus_y = FieldElement::one();

    one_minus_y = &one_minus_y - &AY;

    one_minus_y = one_minus_y.invert();

    let mut x = FieldElement::one();

    x = &x + &AY;

    x = &x * &one_minus_y;

    x.to_bytes()
}

// Convert ed25519 secret key to curve25519
pub fn ed25519_sk_to_curve25519(sk: [u8; 32]) -> [u8; 32] {
    let mut h = sha512::sha512(&sk);

    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    let mut result = [0u8; 32];
    result.copy_from_slice(&h[..32]);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_PK: [u8; 32] = [
        59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119,
        29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
    ];
    const CURVE25519_PK: [u8; 32] = [
        91, 245, 92, 115, 184, 46, 190, 34, 190, 128, 243, 67, 6, 103, 175, 87, 15, 174, 37, 86,
        166, 65, 94, 107, 48, 212, 6, 83, 0, 170, 148, 125,
    ];

    const ED25519_SK: [u8; 32] = [
        202, 104, 239, 81, 53, 110, 80, 252, 198, 23, 155, 162, 215, 98, 223, 173, 227, 188, 110,
        54, 127, 45, 185, 206, 174, 29, 44, 147, 76, 66, 196, 195,
    ];
    const CURVE25519_SK: [u8; 32] = [
        200, 255, 64, 61, 17, 52, 112, 33, 205, 71, 186, 13, 131, 12, 241, 136, 223, 5, 152, 40,
        95, 187, 83, 168, 142, 10, 234, 215, 70, 210, 148, 104,
    ];

    #[test]
    fn test_ed25519_pk_to_curve25519() {
        assert_eq!(ed25519_pk_to_curve25519(ED25519_PK), CURVE25519_PK);
    }

    #[test]
    fn test_ed25519_sk_to_curve25519() {
        assert_eq!(ed25519_sk_to_curve25519(ED25519_SK), CURVE25519_SK);
    }
}
