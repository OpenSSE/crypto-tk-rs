use std::convert::TryFrom;

use super::errors::*;

#[cfg(test)]
use {strum::IntoEnumIterator, strum_macros::EnumIter};

use crate::{rcprf::*, Key, KeyDerivationPrg, Prf, Prg};

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(test, derive(EnumIter))]
pub(crate) enum SerializationTag {
    PrfTag = 1,
    PrgTag,
    KeyDerivationPrgTag,
    RCPrfTag,
    ConstrainedRCPrfTag,
    ConstrainedRCPrfLeafElementTag,
    ConstrainedRCPrfInnerElementTag,
}

impl TryFrom<u16> for SerializationTag {
    type Error = SerializationTagConversionError;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == SerializationTag::PrfTag as u16 => {
                Ok(SerializationTag::PrfTag)
            }
            x if x == SerializationTag::PrgTag as u16 => {
                Ok(SerializationTag::PrgTag)
            }
            x if x == SerializationTag::KeyDerivationPrgTag as u16 => {
                Ok(SerializationTag::KeyDerivationPrgTag)
            }
            x if x == SerializationTag::RCPrfTag as u16 => {
                Ok(SerializationTag::RCPrfTag)
            }
            x if x == SerializationTag::ConstrainedRCPrfTag as u16 => {
                Ok(SerializationTag::ConstrainedRCPrfTag)
            }
            x if x
                == SerializationTag::ConstrainedRCPrfLeafElementTag as u16 =>
            {
                Ok(SerializationTag::ConstrainedRCPrfLeafElementTag)
            }
            x if x
                == SerializationTag::ConstrainedRCPrfInnerElementTag as u16 =>
            {
                Ok(SerializationTag::ConstrainedRCPrfInnerElementTag)
            }
            _ => Err(SerializationTagConversionError(v)),
        }
    }
}

impl SerializationTag {
    pub const SERIALIZATION_SIZE: usize = 2;

    pub(crate) fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<usize> {
        let value = *self as u16;
        writer.write_all(&value.to_le_bytes())?;

        Ok(SerializationTag::SERIALIZATION_SIZE)
    }

    pub(crate) fn read_tag(
        reader: &mut dyn std::io::Read,
    ) -> Result<SerializationTag, SerializationTagDeserializationError> {
        let mut buf = [0u8; 2];

        reader.read_exact(&mut buf)?;
        let v = u16::from_le_bytes(buf);
        Ok(SerializationTag::try_from(v)?)
    }
}

pub(crate) trait SerializableTagged {
    fn serialization_tag(&self) -> SerializationTag;
}

impl SerializableTagged for Prf {
    fn serialization_tag(&self) -> SerializationTag {
        SerializationTag::PrfTag
    }
}

impl SerializableTagged for Prg {
    fn serialization_tag(&self) -> SerializationTag {
        SerializationTag::PrgTag
    }
}

impl<T: Key> SerializableTagged for KeyDerivationPrg<T> {
    fn serialization_tag(&self) -> SerializationTag {
        SerializationTag::KeyDerivationPrgTag
    }
}

impl SerializableTagged for RCPrf {
    fn serialization_tag(&self) -> SerializationTag {
        SerializationTag::RCPrfTag
    }
}

impl SerializableTagged for ConstrainedRCPrf {
    fn serialization_tag(&self) -> SerializationTag {
        SerializationTag::ConstrainedRCPrfTag
    }
}

impl SerializableTagged for leaf_element::ConstrainedRCPrfLeafElement {
    fn serialization_tag(&self) -> SerializationTag {
        SerializationTag::ConstrainedRCPrfLeafElementTag
    }
}

impl SerializableTagged for inner_element::ConstrainedRCPrfInnerElement {
    fn serialization_tag(&self) -> SerializationTag {
        SerializationTag::ConstrainedRCPrfInnerElementTag
    }
}

#[cfg(test)]
mod tests {
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
        match SerializationTag::try_from(25) {
            Ok(_) => panic!("Should return an error"),
            Err(_) => (),
        }
    }
}
