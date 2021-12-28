//! Compatibility module for old (pre-7.0) types

use super::{Class, Header, Length, Tag};

pub type BerClass = Class;
pub type BerSize = Length;
pub type BerTag = Tag;
pub type BerObjectHeader<'a> = Header<'a>;
