use std::error::Error;
use std::fmt;
use thiserror::Error;

#[derive(Debug)]
pub struct SerializationTagConversionError(pub u16);

impl fmt::Display for SerializationTagConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid tag value ({})", self.0)
    }
}

impl Error for SerializationTagConversionError {}

#[derive(Debug, Error)]
pub enum SerializationTagDeserializationError {
    #[error("Tag Deserialization Error - Tag Conversion Error: {0}")]
    ConversionError(#[from] SerializationTagConversionError),
    #[error("Tag Deserialization Error - IO Error: {0}")]
    IOError(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum CleartextContentDeserializationError {
    #[error("Cleartext Content Deserialization Error - ContentError: {0}")]
    ContentError(String),
    #[error("Cleartext Content Deserialization Error - IO Error: {0}")]
    IOError(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum CleartextDeserializationError {
    #[error(transparent)]
    TagError(#[from] SerializationTagDeserializationError),
    #[error(transparent)]
    ContentDeserializationError(#[from] CleartextContentDeserializationError),
}
