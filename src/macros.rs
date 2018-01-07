/// Internal parser, do not use directly
#[doc(hidden)]
#[macro_export]
macro_rules! fold_der_defined_m(
    (__impl $i:expr, $acc:ident, $f:ident) => ( {
        match $f($i) {
            IResult::Done(rem,res) => { $acc.push(res); IResult::Done(rem,$acc) },
            IResult::Incomplete(i) => IResult::Incomplete(i),
            IResult::Error(e)      => IResult::Error(e),
        }
    });
    (__impl $i:expr, $acc:ident, $submac:ident!( $($args:tt)* ) ) => ( {
        match $submac!($i, $($args)*) {
            IResult::Done(rem,res) => { $acc.push(res); IResult::Done(rem,$acc) },
            IResult::Incomplete(i) => IResult::Incomplete(i),
            IResult::Error(e)      => IResult::Error(e),
        }
    });
    (__impl $i:expr, $acc:ident, $f:ident >> $($rest:tt)*) => (
        {
            match $f($i) {
                IResult::Done(rem,res) => {
                    $acc.push(res);
                    fold_der_defined_m!(__impl rem, $acc, $($rest)* )
                },
                IResult::Incomplete(i) => IResult::Incomplete(i),
                IResult::Error(e)      => IResult::Error(e),
            }
        }
    );
    (__impl $i:expr, $acc:ident, $submac:ident!( $($args:tt)* ) >> $($rest:tt)*) => (
        {
            match $submac!($i, $($args)*) {
                IResult::Done(rem,res) => {
                    $acc.push(res);
                    fold_der_defined_m!(__impl rem, $acc, $($rest)* )
                },
                IResult::Incomplete(i) => IResult::Incomplete(i),
                IResult::Error(e)      => IResult::Error(e),
            }
        }
    );

    ($i:expr, $($rest:tt)* ) => (
        {
            let mut v = Vec::new();
            fold_der_defined_m!(__impl $i, v, $($rest)*)
        }
    );
);

/// Parse a sequence of DER elements
///
/// Unlike [parse_der_sequence](fn.parse_der_sequence.html), this function allows to specify the
/// list of expected types in the DER sequence.
///
/// Similar to [parse_der_defined](macro.parse_der_defined.html), but not using `fold`.
/// This allow using macros.
///
/// ```rust,no_run
/// # #[macro_use] extern crate nom;
/// # #[macro_use] extern crate rusticata_macros;
/// # #[macro_use] extern crate der_parser;
/// use der_parser::*;
/// use nom::{IResult,Err,ErrorKind};
///
/// # fn main() {
/// fn localparse_seq(i:&[u8]) -> IResult<&[u8],DerObject> {
///     parse_der_defined_m!(i, 0x10,
///         parse_der_integer >>
///         call!(parse_der_integer)
///     )
/// }
/// let empty = &b""[..];
/// let bytes = [ 0x30, 0x0a,
///               0x02, 0x03, 0x01, 0x00, 0x01,
///               0x02, 0x03, 0x01, 0x00, 0x00,
/// ];
/// let expected  = DerObject::from_obj(DerObjectContent::Sequence(vec![
///     DerObject::from_int_slice(b"\x01\x00\x01"),
///     DerObject::from_int_slice(b"\x01\x00\x00"),
/// ]));
/// assert_eq!(localparse_seq(&bytes), IResult::Done(empty, expected));
/// # }
/// ```
#[macro_export]
macro_rules! parse_der_defined_m(
    ($i:expr, $tag:expr, $($args:tt)*) => (
        {
            use $crate::der_read_element_header;
            do_parse!(
                $i,
                hdr:     der_read_element_header >>
                         error_if!(hdr.elt.class != 0b00, Err::Code(ErrorKind::Custom(128))) >>
                         error_if!(hdr.elt.structured != 0b1, Err::Code(ErrorKind::Custom(129))) >>
                         error_if!(hdr.elt.tag != $tag, Err::Code(ErrorKind::Custom(130))) >>
                content: flat_map!(take!(hdr.len), fold_der_defined_m!( $($args)* )) >>
                ( {
                    $crate::DerObject::from_header_and_content(hdr,$crate::DerObjectContent::Sequence(content))
                } )
            )
        }
    );
);




#[macro_export]
macro_rules! fold_parsers(
    ($i:expr, $($args:tt)*) => (
        {
            let parsers = [ $($args)* ];
            parsers.iter().fold(
                (IResult::Done($i,vec![])),
                |r, f| {
                    match r {
                        IResult::Done(rem,mut v) => {
                            map!(rem, f, |x| { v.push(x); v })
                        }
                        IResult::Incomplete(e) => IResult::Incomplete(e),
                        IResult::Error(e)      => IResult::Error(e),
                    }
                }
                )
        }
    );
);

#[macro_export]
macro_rules! parse_der_defined(
    ($i:expr, $ty:expr, $($args:tt)*) => (
        {
            use $crate::der_read_element_header;
            let res =
            do_parse!(
                $i,
                hdr:     der_read_element_header >>
                         error_if!(hdr.elt.class != 0b00, Err::Code(ErrorKind::Custom(128))) >>
                         error_if!(hdr.elt.structured != 0b1, Err::Code(ErrorKind::Custom(129))) >>
                         error_if!(hdr.elt.tag != $ty, Err::Code(ErrorKind::Custom(130))) >>
                content: take!(hdr.len) >>
                ( (hdr,content) )
            );
            match res {
                IResult::Done(_rem,o)   => {
                    match fold_parsers!(o.1, $($args)* ) {
                        IResult::Done(rem,v)   => {
                            if rem.len() != 0 { IResult::Error(Err::Code(ErrorKind::Custom(131))) }
                            else { IResult::Done(_rem,(o.0,v)) }
                        },
                        IResult::Incomplete(e) => IResult::Incomplete(e),
                        IResult::Error(e)      => IResult::Error(e),
                    }
                },
                IResult::Incomplete(e) => IResult::Incomplete(e),
                IResult::Error(e)      => IResult::Error(e),
            }
        }
    );
);

#[macro_export]
macro_rules! parse_der_sequence_defined(
    ($i:expr, $($args:tt)*) => (
        map!(
            $i,
            parse_der_defined!(0x10, $($args)*),
            |(hdr,o)| $crate::DerObject::from_header_and_content(hdr,$crate::DerObjectContent::Sequence(o))
        )
    );
);

#[macro_export]
macro_rules! parse_der_set_defined(
    ($i:expr, $($args:tt)*) => (
        map!(
            $i,
            parse_der_defined!(0x11, $($args)*),
            |(hdr,o)| $crate::DerObject::from_header_and_content(hdr,$crate::DerObjectContent::Set(o))
        )
    );
);

#[macro_export]
macro_rules! parse_der_sequence_of(
    ($i:expr, $f:ident) => ({
        use $crate::der_read_element_header;
        do_parse!(
            $i,
            hdr:     der_read_element_header >>
                     error_if!(hdr.elt.tag != DerTag::Sequence as u8, Err::Code(ErrorKind::Custom(128))) >>
            content: flat_map!(take!(hdr.len),
                do_parse!(
                    r: many0!($f) >>
                       eof!() >>
                    ( r )
                )
            ) >>
            ( $crate::DerObject::from_header_and_content(hdr, $crate::DerObjectContent::Sequence(content)) )
        )
    })
);

#[macro_export]
macro_rules! parse_der_set_of(
    ($i:expr, $f:ident) => ({
        use $crate::der_read_element_header;
        do_parse!(
            $i,
            hdr:     der_read_element_header >>
                     error_if!(hdr.elt.tag != DerTag::Set as u8, Err::Code(ErrorKind::Custom(128))) >>
            content: flat_map!(take!(hdr.len),
                do_parse!(
                    r: many0!($f) >>
                       eof!() >>
                    ( r )
                )
            ) >>
            ( $crate::DerObject::from_header_and_content(hdr, $crate::DerObjectContent::Sequence(content)) )
        )
    })
);

#[macro_export]
macro_rules! parse_der_optional(
    ($i:expr, $f:ident) => (
        alt_complete!(
            $i,
            do_parse!(
                content: call!($f) >>
                (
                    $crate::DerObject::from_obj(
                        $crate::DerObjectContent::ContextSpecific(0 /* XXX */,Some(Box::new(content)))
                    )
                )
            ) |
            apply!(parse_der_explicit_failed,0 /* XXX */)
        )
    )
);
