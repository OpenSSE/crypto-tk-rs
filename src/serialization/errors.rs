use std::error::Error;
use std::fmt;
use thiserror::Error;

/// An error occurring when converting an integer to a Serialization tag
#[derive(Debug)]
pub struct SerializationTagConversionError(pub u16);

impl fmt::Display for SerializationTagConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid tag value ({})", self.0)
    }
}

impl Error for SerializationTagConversionError {}

/// Error occurring during the deserialization of a tag
#[derive(Debug, Error)]
pub enum SerializationTagDeserializationError {
    /// Tag conversion error
    #[error("Tag Deserialization Error - Tag Conversion Error: {0}")]
    ConversionError(#[from] SerializationTagConversionError),
    /// IO error
    #[error("Tag Deserialization Error - IO Error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Error occuring during the deserialization of an object's content
#[derive(Debug, Error)]
pub enum CleartextContentDeserializationError {
    /// Logical error during the content's deserialization
    #[error("Cleartext Content Deserialization Error - ContentError: {0}")]
    ContentError(String),
    /// IO error
    #[error("Cleartext Content Deserialization Error - IO Error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Error occuring during the deserialization of an object
#[derive(Debug, Error)]
pub enum CleartextDeserializationError {
    /// Error during the tag's deserialization
    #[error(transparent)]
    TagError(#[from] SerializationTagDeserializationError),
    /// Serialization tag not matching the deserialized object's type
    #[error("Deserialized tag do not match the object type")]
    InvalidTagError(crate::serialization::tags::SerializationTag),
    /// Error during the content's deserialization
    #[error(transparent)]
    ContentDeserializationError(#[from] CleartextContentDeserializationError),
}
