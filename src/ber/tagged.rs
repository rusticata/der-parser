use crate::ber::*;
use crate::error::*;
use nom::{Err, IResult};

/// Read a TAGGED EXPLICIT value (function version)
///
/// The following parses `[2] EXPLICIT INTEGER`:
///
/// ```rust
/// # use der_parser::ber::*;
/// # use der_parser::error::BerResult;
/// use nom::combinator::map_res;
/// #
/// fn parse_int_explicit(i:&[u8]) -> BerResult<u32> {
///     parse_ber_tagged_explicit(
///         2,
///         parse_ber_u32
///     )(i)
/// }
///
/// # let bytes = &[0xa2, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01];
/// let res = parse_int_explicit(bytes);
/// # match res {
/// #     Ok((rem,val)) => {
/// #         assert!(rem.is_empty());
/// #         assert_eq!(val, 0x10001);
/// #     },
/// #     _ => assert!(false)
/// # }
/// ```
pub fn parse_ber_tagged_explicit<'a, Tag, Output, F, E>(
    tag: Tag,
    f: F,
) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Output, E>
where
    F: Fn(&'a [u8]) -> IResult<&'a [u8], Output, E>,
    E: nom::error::ParseError<&'a [u8]> + From<BerError>,
    Tag: Into<BerTag>,
{
    let tag = tag.into();
    parse_ber_container(move |hdr, i| {
        if hdr.tag != tag {
            return Err(Err::Error(BerError::InvalidTag.into()));
        }
        // X.690 8.14.2: if implificit tagging was not used, the encoding shall be constructed
        if !hdr.is_constructed() {
            return Err(Err::Error(BerError::ConstructExpected.into()));
        }
        f(i)
        // trailing bytes are ignored
    })
}

/// Read a TAGGED IMPLICIT value (function version)
///
/// The following parses `[2] IMPLICIT INTEGER`:
///
/// ```rust
/// # use der_parser::ber::*;
/// # use der_parser::error::BerResult;
/// use nom::combinator::map_res;
/// #
/// fn parse_int_implicit(i:&[u8]) -> BerResult<u32> {
///     map_res(
///         parse_ber_tagged_implicit(
///             2,
///             parse_ber_content(BerTag::Integer),
///         ),
///         |x: BerObjectContent| x.as_u32()
///     )(i)
/// }
///
/// # let bytes = &[0x82, 0x03, 0x01, 0x00, 0x01];
/// let res = parse_int_implicit(bytes);
/// # match res {
/// #     Ok((rem,val)) => {
/// #         assert!(rem.is_empty());
/// #         assert_eq!(val, 0x10001);
/// #     },
/// #     _ => assert!(false)
/// # }
/// ```
pub fn parse_ber_tagged_implicit<'a, Tag, Output, F, E>(
    tag: Tag,
    f: F,
) -> impl Fn(&'a [u8]) -> IResult<&[u8], Output, E>
where
    F: Fn(&'a [u8], &'_ BerObjectHeader, usize) -> IResult<&'a [u8], Output, E>,
    E: nom::error::ParseError<&'a [u8]> + From<BerError>,
    Tag: Into<BerTag>,
{
    let tag = tag.into();
    parse_ber_container(move |hdr, i| {
        if hdr.tag != tag {
            return Err(Err::Error(BerError::InvalidTag.into()));
        }
        // XXX MAX_RECURSION should not be used, it resets the depth counter
        f(i, &hdr, MAX_RECURSION)
        // trailing bytes are ignored
    })
}
