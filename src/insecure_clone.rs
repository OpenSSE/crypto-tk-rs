pub(crate) mod private {
    pub trait InsecureClone: Sized {
        /// Duplicates the object.
        /// Would be similar to `clone()`, except we want to make sure that the
        /// user knows this leads to security issues.
        fn insecure_clone(&self) -> Self;
    }
}

/// Specific trait to clone cryptographic objects.
/// This is introduced to avoind implicitely clone objects and always make sure a clone deliberately comes from a user
pub trait CryptographyClone: private::InsecureClone {
    /// Clone the cryptographic object
    #[must_use]
    fn cryptography_clone(&self) -> Self {
        self.insecure_clone()
    }
}
