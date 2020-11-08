pub(crate) mod private {
    pub trait InsecureClone {
        /// Duplicates the object.
        /// Would be similar to `clone()`, except we want to make sure that the user knows this leads to security issues.
        /// This function is only available in `test` mode (it should not be used in production code).
        fn insecure_clone(&self) -> Self;
    }
}
