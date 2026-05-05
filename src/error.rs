// Public error surface exported through UniFFI. Kept as an enum (rather
// than a unit struct) so the variant set can grow without breaking the
// generated Kotlin / Swift / TypeScript binding shape.

#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum MoproError {
    #[error("CircomError: {0}")]
    CircomError(String),
}
