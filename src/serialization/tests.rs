#![allow(clippy::unwrap_used)]

use super::cleartext_serialization::*;
use crate::*;
use std::io::Cursor;

fn ser_deser<T: DeserializableCleartext + SerializableCleartext>(
    object: &T,
) -> T {
    let mut ser_buffer = vec![];
    let written_bytes = object.serialize_cleartext(&mut ser_buffer).unwrap();

    assert_eq!(written_bytes, ser_buffer.len());
    let mut cursor = Cursor::new(ser_buffer);
    T::deserialize_cleartext(&mut cursor).unwrap()
}

fn wrap_unwrap<T: Wrappable>(object: &T) -> T {
    let k = Key256::new();
    let wrapper = CryptoWrapper::from_key(k);

    let bytes = wrapper.wrap(object).unwrap();
    wrapper.unwrap(&bytes).unwrap()
}

fn test_prf_identity<F>(fun: F)
where
    F: Fn(&Prf) -> Prf,
{
    let prf = Prf::new();
    let deser_prf = fun(&prf);

    let input = 0u64.to_le_bytes();
    let mut eval_1 = [0u8; 32];
    let mut eval_2 = [0u8; 32];

    prf.fill_bytes(&input, &mut eval_1);
    deser_prf.fill_bytes(&input, &mut eval_2);

    assert_eq!(eval_1, eval_2);
}
#[test]
fn prf_serialization() {
    test_prf_identity(ser_deser);
}

#[test]
fn prf_wrapping() {
    test_prf_identity(wrap_unwrap);
}

fn test_prg_identity<F>(fun: F)
where
    F: Fn(&Prg) -> Prg,
{
    let prg = Prg::new();
    let deser_prg = fun(&prg);

    let mut eval_1 = [0u8; 32];
    let mut eval_2 = [0u8; 32];

    prg.fill_pseudo_random_bytes(&mut eval_1);
    deser_prg.fill_pseudo_random_bytes(&mut eval_2);

    assert_eq!(eval_1, eval_2);
}

#[test]
fn prg_serialization() {
    test_prg_identity(ser_deser);
}

#[test]
fn prg_wrapping() {
    test_prg_identity(wrap_unwrap);
}

fn test_key_derivation_prg_identity<F>(fun: F)
where
    F: Fn(&KeyDerivationPrg<Key256>) -> KeyDerivationPrg<Key256>,
{
    let prg = KeyDerivationPrg::<Key256>::new();
    let deser_prg = fun(&prg);

    let k1 = prg.derive_key(0);
    let k2 = deser_prg.derive_key(0);

    assert_eq!(k1.content(), k2.content());
}

#[test]
fn key_derivation_prg_serialization() {
    test_key_derivation_prg_identity(ser_deser);
}

#[test]
fn key_derivation_prg_wrapping() {
    test_key_derivation_prg_identity(wrap_unwrap);
}

fn test_rcprf_identity<F>(fun: F)
where
    F: Fn(&RcPrf) -> RcPrf,
{
    let rcprf = RcPrf::new(8).unwrap();
    let deser_rcprf = fun(&rcprf);

    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];

    rcprf.eval(0, &mut out1).unwrap();
    deser_rcprf.eval(0, &mut out2).unwrap();

    assert_eq!(out1, out2);
}

#[test]
fn rcprf_serialization() {
    test_rcprf_identity(ser_deser);
}

#[test]
fn rcprf_wrapping() {
    test_rcprf_identity(wrap_unwrap);
}

fn test_constrained_rcprf_identity<F>(fun: F)
where
    F: Fn(&ConstrainedRcPrf) -> ConstrainedRcPrf,
{
    let h = 6u8;

    let rcprf = RcPrf::new(h).unwrap();

    // iterate over all the possible ranges
    for start in 0..=max_leaf_index(h) {
        for end in start..=max_leaf_index(h) {
            let range = RcPrfRange::new(start, end);
            let constrained_rcprf = rcprf.constrain(&range).unwrap();
            let deser_constrained_rcprf = fun(&constrained_rcprf);

            let constrained_eval_0: Vec<[u8; 16]> = (start..=end)
                .map(|x| {
                    let mut out = [0u8; 16];

                    constrained_rcprf.eval(x, &mut out).unwrap();
                    out
                })
                .collect();

            let constrained_eval_1: Vec<[u8; 16]> = (start..=end)
                .map(|x| {
                    let mut out = [0u8; 16];

                    deser_constrained_rcprf.eval(x, &mut out).unwrap();
                    out
                })
                .collect();

            assert_eq!(constrained_eval_0, constrained_eval_1);
        }
    }
}

#[test]
fn constrained_rcprf_serialization() {
    test_constrained_rcprf_identity(ser_deser);
}

#[test]
fn constrained_rcprf_wrapping() {
    test_constrained_rcprf_identity(wrap_unwrap);
}

const TEST_PLAINTEXT: &[u8] = b"Test plaintext";

fn test_cipher_identity<F>(fun: F)
where
    F: Fn(&Cipher) -> Cipher,
{
    let k = Key256::new();
    let cipher = Cipher::from_key(k);

    let deser_cipher = fun(&cipher);

    let plaintext = TEST_PLAINTEXT;
    let mut ciphertext =
        vec![0u8; plaintext.len() + Cipher::CIPHERTEXT_EXPANSION];
    let mut dec_result = vec![0u8; plaintext.len()];

    cipher.encrypt(plaintext, &mut ciphertext).unwrap();

    deser_cipher.decrypt(&ciphertext, &mut dec_result).unwrap();

    assert_eq!(plaintext, &dec_result[..]);
}

#[test]
fn cipher_serialization() {
    test_cipher_identity(ser_deser);
}

#[test]
fn cipher_wrapping() {
    test_cipher_identity(wrap_unwrap);
}

fn test_aead_cipher_identity<F>(fun: F)
where
    F: Fn(&AeadCipher) -> AeadCipher,
{
    let k = Key256::new();
    let cipher = AeadCipher::from_key(k);

    let deser_cipher = fun(&cipher);

    let plaintext = TEST_PLAINTEXT;
    let mut ciphertext =
        vec![0u8; plaintext.len() + AeadCipher::CIPHERTEXT_EXPANSION];
    let mut dec_result = vec![0u8; plaintext.len()];

    cipher.encrypt(plaintext, &mut ciphertext).unwrap();

    deser_cipher.decrypt(&ciphertext, &mut dec_result).unwrap();

    assert_eq!(plaintext, &dec_result[..]);
}

#[test]
fn aead_cipher_serialization() {
    test_aead_cipher_identity(ser_deser);
}

#[test]
fn aead_cipher_wrapping() {
    test_cipher_identity(wrap_unwrap);
}
