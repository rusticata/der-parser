#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ClassFromIntError(pub(crate) ());

/// BER Object class of tag
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum Class {
    Universal = 0b00,
    Application = 0b01,
    ContextSpecific = 0b10,
    Private = 0b11,
}
