use crate::tags::SerializationTag;

use super::errors::*;
use super::tags::*;

pub trait SerializableCleartextContent {
    fn serialization_content_byte_size(&self) -> usize;
    fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error>;
}

pub trait DeserializableCleartextContent: Sized {
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError>;
}

pub trait SerializableCleartext:
    SerializableCleartextContent + SerializationTagged
{
    fn cleartext_serialization_length(&self) -> usize {
        self.serialization_content_byte_size()
            + SerializationTag::SERIALIZATION_SIZE
    }

    fn serialize_cleartext(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        // serialize the tag first
        let tag = self.serialization_tag();
        let mut b = tag.serialize_content(writer)?;
        b += self.serialize_content(writer)?;

        Ok(b)
    }
}
impl<T> SerializableCleartext for T where
    T: SerializableCleartextContent + SerializationTagged
{
}

pub trait DeserializableCleartext:
    DeserializableCleartextContent + SerializationTaggedType
{
    fn deserialize_cleartext(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextDeserializationError> {
        let tag = SerializationTag::read_tag(reader)?;

        if tag == Self::serialization_tag() {
            Ok(Self::deserialize_content(reader)?)
        } else {
            Err(CleartextDeserializationError::InvalidTagError(tag))
        }
    }
}
impl<T> DeserializableCleartext for T where
    T: DeserializableCleartextContent + SerializationTaggedType
{
}
