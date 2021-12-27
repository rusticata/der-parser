#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BerSizeError(pub(crate) ());

/// Ber Object Length
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Length {
    /// Definite form (X.690 8.1.3.3)
    Definite(usize),
    /// Indefinite form (X.690 8.1.3.6)
    Indefinite,
}
