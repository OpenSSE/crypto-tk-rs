use std::convert::TryFrom;

use super::errors::*;

use crate::{rcprf::*, AeadCipher, Cipher, Key, KeyDerivationPrg, Prf, Prg};
#[cfg(test)]
use {strum::IntoEnumIterator, strum_macros::EnumIter};

/// Tag encoding the type of a serialized cryptographic object
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(EnumIter))]
pub enum SerializationTag {
    Prf = 1,
    Prg,
    KeyDerivationPrg,
    RcPrf,
    ConstrainedRcPrf,
    ConstrainedRcPrfLeafElement,
    ConstrainedRcPrfInnerElement,
    Cipher,
    AeadCipher,
}

impl TryFrom<u16> for SerializationTag {
    type Error = SerializationTagConversionError;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == SerializationTag::Prf as u16 => Ok(SerializationTag::Prf),
            x if x == SerializationTag::Prg as u16 => Ok(SerializationTag::Prg),
            x if x == SerializationTag::KeyDerivationPrg as u16 => {
                Ok(SerializationTag::KeyDerivationPrg)
            }
            x if x == SerializationTag::RcPrf as u16 => {
                Ok(SerializationTag::RcPrf)
            }
            x if x == SerializationTag::ConstrainedRcPrf as u16 => {
                Ok(SerializationTag::ConstrainedRcPrf)
            }
            x if x == SerializationTag::ConstrainedRcPrfLeafElement as u16 => {
                Ok(SerializationTag::ConstrainedRcPrfLeafElement)
            }
            x if x == SerializationTag::ConstrainedRcPrfInnerElement as u16 => {
                Ok(SerializationTag::ConstrainedRcPrfInnerElement)
            }
            x if x == SerializationTag::Cipher as u16 => {
                Ok(SerializationTag::Cipher)
            }
            x if x == SerializationTag::AeadCipher as u16 => {
                Ok(SerializationTag::AeadCipher)
            }
            _ => Err(SerializationTagConversionError(v)),
        }
    }
}

impl SerializationTag {
    pub const SERIALIZATION_SIZE: usize = 2;

    /// Write the tag to an IO stream
    pub(crate) fn serialize_content(
        self,
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<usize> {
        let value = self as u16;
        writer.write_all(&value.to_le_bytes())?;

        Ok(SerializationTag::SERIALIZATION_SIZE)
    }

    /// Read a tag from a byte stream (represented as an IO object)
    #[allow(dead_code)]
    pub(crate) fn read_tag(
        reader: &mut dyn std::io::Read,
    ) -> Result<SerializationTag, SerializationTagError> {
        let mut buf = [0u8; 2];

        reader.read_exact(&mut buf)?;
        let v = u16::from_le_bytes(buf);
        Ok(SerializationTag::try_from(v)?)
    }
}

pub trait SerializationTaggedType {
    fn serialization_tag() -> SerializationTag;
}

impl SerializationTaggedType for Prf {
    fn serialization_tag() -> SerializationTag {
        SerializationTag::Prf
    }
}

impl SerializationTaggedType for Prg {
    fn serialization_tag() -> SerializationTag {
        SerializationTag::Prg
    }
}

impl<T: Key> SerializationTaggedType for KeyDerivationPrg<T> {
    fn serialization_tag() -> SerializationTag {
        SerializationTag::KeyDerivationPrg
    }
}

impl SerializationTaggedType for RcPrf {
    fn serialization_tag() -> SerializationTag {
        SerializationTag::RcPrf
    }
}

impl SerializationTaggedType for ConstrainedRcPrf {
    fn serialization_tag() -> SerializationTag {
        SerializationTag::ConstrainedRcPrf
    }
}

impl SerializationTaggedType for leaf_element::ConstrainedRcPrfLeafElement {
    fn serialization_tag() -> SerializationTag {
        SerializationTag::ConstrainedRcPrfLeafElement
    }
}

impl SerializationTaggedType for inner_element::ConstrainedRcPrfInnerElement {
    fn serialization_tag() -> SerializationTag {
        SerializationTag::ConstrainedRcPrfInnerElement
    }
}

impl SerializationTaggedType for Cipher {
    fn serialization_tag() -> SerializationTag {
        SerializationTag::Cipher
    }
}

impl SerializationTaggedType for AeadCipher {
    fn serialization_tag() -> SerializationTag {
        SerializationTag::AeadCipher
    }
}

pub trait SerializationTagged {
    fn serialization_tag(&self) -> SerializationTag;
}

impl<T: SerializationTaggedType> SerializationTagged for T {
    fn serialization_tag(&self) -> SerializationTag {
        T::serialization_tag()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_serialization() {
        for tag in SerializationTag::iter() {
            let mut buffer: Vec<u8> = vec![];
            tag.serialize_content(&mut buffer).unwrap();

            let deserialized_tag =
                SerializationTag::read_tag(&mut &buffer[..]).unwrap();

            assert_eq!(tag, deserialized_tag);
        }
    }

    #[test]
    fn pairwise_distinct_tag_values() {
        for t1 in SerializationTag::iter() {
            for t2 in SerializationTag::iter() {
                if t1 != t2 {
                    assert_ne!(t1 as u16, t2 as u16);
                }
            }
        }
    }

    #[test]
    fn errors() {
        SerializationTag::try_from(25)
            .expect_err("Invalid tag, error not raised");
    }
}
