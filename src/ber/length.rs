use crate::error::BerError;
use core::convert::TryFrom;

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

impl Length {
    /// Return true if length is definite and equal to 0
    pub fn is_null(&self) -> bool {
        *self == Length::Definite(0)
    }

    /// Get length of primitive object
    #[inline]
    pub fn primitive(&self) -> Result<usize, BerError> {
        match self {
            Length::Definite(sz) => Ok(*sz),
            Length::Indefinite => Err(BerError::IndefiniteLengthUnexpected),
        }
    }
}

impl From<usize> for Length {
    fn from(v: usize) -> Self {
        Length::Definite(v)
    }
}

impl TryFrom<u64> for Length {
    type Error = BerSizeError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let v = usize::try_from(value).or(Err(BerSizeError(())))?;
        Ok(Length::Definite(v))
    }
}

impl TryFrom<Length> for usize {
    type Error = BerSizeError;

    #[inline]
    fn try_from(value: Length) -> Result<Self, Self::Error> {
        match value {
            Length::Definite(sz) => Ok(sz),
            Length::Indefinite => Err(BerSizeError(())),
        }
    }
}
