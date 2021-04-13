use super::cleartext_serialization::*;
use crate::*;
use std::io::Cursor;

#[test]
fn prf_serialization() {
    let prf = Prf::new();

    let mut ser_buffer = vec![];
    let written_bytes = prf.serialize_cleartext(&mut ser_buffer).unwrap();

    assert_eq!(written_bytes, ser_buffer.len());
    let mut cursor = Cursor::new(ser_buffer);
    let deser_prf = Prf::deserialize_cleartext(&mut cursor).unwrap();

    let input = 0u64.to_le_bytes();
    let mut eval_1 = [0u8; 32];
    let mut eval_2 = [0u8; 32];

    prf.fill_bytes(&input, &mut eval_1);
    deser_prf.fill_bytes(&input, &mut eval_2);

    assert_eq!(eval_1, eval_2);
}

#[test]
fn prg_serialization() {
    let prg = Prg::new();

    let mut ser_buffer = vec![];
    let written_bytes = prg.serialize_cleartext(&mut ser_buffer).unwrap();

    assert_eq!(written_bytes, ser_buffer.len());
    let mut cursor = Cursor::new(ser_buffer);
    let deser_prg = Prg::deserialize_cleartext(&mut cursor).unwrap();

    let mut eval_1 = [0u8; 32];
    let mut eval_2 = [0u8; 32];

    prg.fill_pseudo_random_bytes(&mut eval_1);
    deser_prg.fill_pseudo_random_bytes(&mut eval_2);

    assert_eq!(eval_1, eval_2);
}

#[test]
fn key_derivation_prg_serialization() {
    let prg = KeyDerivationPrg::<Key256>::new();

    let mut ser_buffer = vec![];
    let written_bytes = prg.serialize_cleartext(&mut ser_buffer).unwrap();

    assert_eq!(written_bytes, ser_buffer.len());
    let mut cursor = Cursor::new(ser_buffer);
    let deser_prg =
        KeyDerivationPrg::<Key256>::deserialize_cleartext(&mut cursor).unwrap();

    let k1 = prg.derive_key(0);
    let k2 = deser_prg.derive_key(0);

    assert_eq!(k1.content(), k2.content());
}

#[test]
fn rcprf_serialization() {
    let rcprf = RCPrf::new(8).unwrap();

    let mut ser_buffer = vec![];
    let written_bytes = rcprf.serialize_cleartext(&mut ser_buffer).unwrap();

    assert_eq!(written_bytes, ser_buffer.len());
    let mut cursor = Cursor::new(ser_buffer);
    let deser_rcprf = RCPrf::deserialize_cleartext(&mut cursor).unwrap();

    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];

    rcprf.eval(0, &mut out1).unwrap();
    deser_rcprf.eval(0, &mut out2).unwrap();

    assert_eq!(out1, out2);
}

#[test]
fn constrained_rcprf_serialization() {
    let h = 6u8;

    let rcprf = RCPrf::new(h).unwrap();

    // iterate over all the possible ranges
    for start in 0..=max_leaf_index(h) {
        for end in start..=max_leaf_index(h) {
            let range = RCPrfRange::new(start, end);
            let constrained_rcprf = rcprf.constrain(&range).unwrap();

            let mut ser_buffer = vec![];
            let written_bytes = constrained_rcprf
                .serialize_cleartext(&mut ser_buffer)
                .unwrap();

            assert_eq!(written_bytes, ser_buffer.len());
            let mut cursor = Cursor::new(ser_buffer);
            let deser_constrained_rcprf =
                ConstrainedRCPrf::deserialize_cleartext(&mut cursor).unwrap();

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
