pub(crate) mod private {
    pub trait InsecureClone {
        /// Duplicates the object.
        /// Would be similar to `clone()`, except we want to make sure that the
        /// user knows this leads to security issues.
        fn insecure_clone(&self) -> Self;
    }
}
