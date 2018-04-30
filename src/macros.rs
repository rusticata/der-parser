/// Combination and flat_map! and take! as first combinator
#[macro_export]
macro_rules! flat_take (
    ($i:expr, $len:expr, $f:ident) => ({
        use nom::Needed;
        if $i.len() < $len { IResult::Incomplete(Needed::Size($len)) }
        else {
            let taken = &$i[0..$len];
            let rem = &$i[$len..];
            match $f(taken) {
                IResult::Done(_,res)   => IResult::Done(rem,res),
                IResult::Incomplete(i) => IResult::Incomplete(i),
                IResult::Error(e)      => IResult::Error(e),
            }
        }
    });
    ($i:expr, $len:expr, $submac:ident!( $($args:tt)*)) => ({
        use nom::Needed;
        if $i.len() < $len { IResult::Incomplete(Needed::Size($len)) }
        else {
            let taken = &$i[0..$len];
            let rem = &$i[$len..];
            match $submac!(taken, $($args)*) {
                IResult::Done(_,res)   => IResult::Done(rem,res),
                IResult::Incomplete(i) => IResult::Incomplete(i),
                IResult::Error(e)      => IResult::Error(e),
            }
        }
    });
);

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

/// Internal parser, do not use directly
#[doc(hidden)]
#[macro_export]
macro_rules! parse_der_defined_m(
    ($i:expr, $tag:expr, $($args:tt)*) => (
        {
            use $crate::der_read_element_header;
            do_parse!(
                $i,
                hdr:     der_read_element_header >>
                         error_if!(hdr.class != 0b00, ErrorKind::Custom($crate::DER_CLASS_ERROR)) >>
                         error_if!(hdr.structured != 0b1, ErrorKind::Custom($crate::DER_STRUCT_ERROR)) >>
                         error_if!(hdr.tag != $tag, ErrorKind::Custom($crate::DER_TAG_ERROR)) >>
                content: flat_take!(hdr.len as usize, fold_der_defined_m!( $($args)* )) >>
                (hdr,content)
            )
        }
    );
);

/// Parse a sequence of DER elements (macro version)
///
/// Unlike [`parse_der_sequence`](fn.parse_der_sequence.html), this function allows to specify the
/// list of expected types in the DER sequence.
///
/// Similar to [`parse_der_sequence_defined`](macro.parse_der_sequence_defined.html), but not using `fold`.
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
///     parse_der_sequence_defined_m!(i,
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
macro_rules! parse_der_sequence_defined_m(
    ($i:expr, $($args:tt)*) => (
        map!(
            $i,
            parse_der_defined_m!(0x10, $($args)*),
            |(hdr,o)| $crate::DerObject::from_header_and_content(hdr,$crate::DerObjectContent::Sequence(o))
        )
    );
);

/// Parse a set of DER elements (macro version)
///
/// Unlike [`parse_der_set`](fn.parse_der_set.html), this function allows to specify the
/// list of expected types in the DER set.
///
/// Similar to [`parse_der_set_defined`](macro.parse_der_set_defined.html), but not using `fold`.
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
/// fn localparse_set(i:&[u8]) -> IResult<&[u8],DerObject> {
///     parse_der_set_defined_m!(i,
///         parse_der_integer >>
///         call!(parse_der_integer)
///     )
/// }
/// let empty = &b""[..];
/// let bytes = [ 0x31, 0x0a,
///               0x02, 0x03, 0x01, 0x00, 0x01,
///               0x02, 0x03, 0x01, 0x00, 0x00,
/// ];
/// let expected  = DerObject::from_obj(DerObjectContent::Set(vec![
///     DerObject::from_int_slice(b"\x01\x00\x01"),
///     DerObject::from_int_slice(b"\x01\x00\x00"),
/// ]));
/// assert_eq!(localparse_set(&bytes), IResult::Done(empty, expected));
/// # }
/// ```
#[macro_export]
macro_rules! parse_der_set_defined_m(
    ($i:expr, $($args:tt)*) => (
        map!(
            $i,
            parse_der_defined_m!(0x11, $($args)*),
            |(hdr,o)| $crate::DerObject::from_header_and_content(hdr,$crate::DerObjectContent::Set(o))
        )
    );
);


/// Internal parser, do not use directly
#[doc(hidden)]
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

/// Internal parser, do not use directly
#[doc(hidden)]
#[macro_export]
macro_rules! parse_der_defined(
    ($i:expr, $ty:expr, $($args:tt)*) => (
        {
            use $crate::der_read_element_header;
            let res =
            do_parse!(
                $i,
                hdr:     der_read_element_header >>
                         error_if!(hdr.class != 0b00, ErrorKind::Custom($crate::DER_CLASS_ERROR)) >>
                         error_if!(hdr.structured != 0b1, ErrorKind::Custom($crate::DER_STRUCT_ERROR)) >>
                         error_if!(hdr.tag != $ty, ErrorKind::Custom($crate::DER_TAG_ERROR)) >>
                content: take!(hdr.len) >>
                (hdr,content)
            );
            match res {
                IResult::Done(_rem,o)   => {
                    match fold_parsers!(o.1, $($args)* ) {
                        IResult::Done(rem,v)   => {
                            if rem.len() != 0 { IResult::Error(error_position!(ErrorKind::Custom(DER_OBJ_TOOSHORT), $i)) }
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

/// Parse a sequence of DER elements (folding version)
///
/// Unlike [`parse_der_sequence`](fn.parse_der_sequence.html), this function allows to specify the
/// list of expected types in the DER sequence.
///
/// Similar to [`parse_der_sequence_defined_m`](macro.parse_der_sequence_defined_m.html), but uses
/// `fold` internally.
/// Because of that, macros cannot be used as subparsers.
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
///     parse_der_sequence_defined!(i,
///         parse_der_integer,
///         parse_der_integer
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
macro_rules! parse_der_sequence_defined(
    ($i:expr, $($args:tt)*) => (
        map!(
            $i,
            parse_der_defined!(0x10, $($args)*),
            |(hdr,o)| $crate::DerObject::from_header_and_content(hdr,$crate::DerObjectContent::Sequence(o))
        )
    );
);

/// Parse a set of DER elements (folding version)
///
/// Unlike [`parse_der_set`](fn.parse_der_set.html), this function allows to specify the
/// list of expected types in the DER sequence.
///
/// Similar to [`parse_der_set_defined_m`](macro.parse_der_set_defined_m.html), but uses
/// `fold` internally.
/// Because of that, macros cannot be used as subparsers.
///
/// ```rust,no_run
/// # #[macro_use] extern crate nom;
/// # #[macro_use] extern crate rusticata_macros;
/// # #[macro_use] extern crate der_parser;
/// use der_parser::*;
/// use nom::{IResult,Err,ErrorKind};
///
/// # fn main() {
/// fn localparse_set(i:&[u8]) -> IResult<&[u8],DerObject> {
///     parse_der_set_defined!(i,
///         parse_der_integer,
///         parse_der_integer
///     )
/// }
/// let empty = &b""[..];
/// let bytes = [ 0x30, 0x0a,
///               0x02, 0x03, 0x01, 0x00, 0x01,
///               0x02, 0x03, 0x01, 0x00, 0x00,
/// ];
/// let expected  = DerObject::from_obj(DerObjectContent::Set(vec![
///     DerObject::from_int_slice(b"\x01\x00\x01"),
///     DerObject::from_int_slice(b"\x01\x00\x00"),
/// ]));
/// assert_eq!(localparse_set(&bytes), IResult::Done(empty, expected));
/// # }
/// ```
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

/// Parse a sequence of identical DER elements
///
/// Given a subparser for a DER type, parse a sequence of identical objects.
///
/// ```rust,no_run
/// # #[macro_use] extern crate nom;
/// # #[macro_use] extern crate rusticata_macros;
/// # #[macro_use] extern crate der_parser;
/// use der_parser::*;
/// use nom::{IResult,Err,ErrorKind};
///
/// # fn main() {
/// fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
///     parse_der_sequence_of!(i, parse_der_integer)
/// };
/// let empty = &b""[..];
/// let bytes = [ 0x30, 0x0a,
///               0x02, 0x03, 0x01, 0x00, 0x01,
///               0x02, 0x03, 0x01, 0x00, 0x00,
/// ];
/// let expected  = DerObject::from_obj(DerObjectContent::Sequence(vec![
///     DerObject::from_int_slice(b"\x01\x00\x01"),
///     DerObject::from_int_slice(b"\x01\x00\x00"),
/// ]));
/// assert_eq!(parser(&bytes), IResult::Done(empty, expected));
/// # }
/// ```
#[macro_export]
macro_rules! parse_der_sequence_of(
    ($i:expr, $f:ident) => ({
        use $crate::der_read_element_header;
        do_parse!(
            $i,
            hdr:     der_read_element_header >>
                     error_if!(hdr.tag != DerTag::Sequence as u8, ErrorKind::Custom($crate::DER_TAG_ERROR)) >>
            content: flat_take!(hdr.len as usize,
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

/// Parse a set of identical DER elements
///
/// Given a subparser for a DER type, parse a set of identical objects.
///
/// ```rust,no_run
/// # #[macro_use] extern crate nom;
/// # #[macro_use] extern crate rusticata_macros;
/// # #[macro_use] extern crate der_parser;
/// use der_parser::*;
/// use nom::{IResult,Err,ErrorKind};
///
/// # fn main() {
/// fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
///     parse_der_set_of!(i, parse_der_integer)
/// };
/// let empty = &b""[..];
/// let bytes = [ 0x30, 0x0a,
///               0x02, 0x03, 0x01, 0x00, 0x01,
///               0x02, 0x03, 0x01, 0x00, 0x00,
/// ];
/// let expected  = DerObject::from_obj(DerObjectContent::Set(vec![
///     DerObject::from_int_slice(b"\x01\x00\x01"),
///     DerObject::from_int_slice(b"\x01\x00\x00"),
/// ]));
/// assert_eq!(parser(&bytes), IResult::Done(empty, expected));
/// # }
/// ```
#[macro_export]
macro_rules! parse_der_set_of(
    ($i:expr, $f:ident) => ({
        use $crate::der_read_element_header;
        do_parse!(
            $i,
            hdr:     der_read_element_header >>
                     error_if!(hdr.tag != DerTag::Set as u8, ErrorKind::Custom($crate::DER_TAG_ERROR)) >>
            content: flat_take!(hdr.len as usize,
                do_parse!(
                    r: many0!($f) >>
                       eof!() >>
                    ( r )
                )
            ) >>
            ( $crate::DerObject::from_header_and_content(hdr, $crate::DerObjectContent::Set(content)) )
        )
    })
);

/// Parse an optional DER element
///
/// Try to parse an optional DER element, and return it as a `ContextSpecific` item with tag 0.
/// If the parsing failed, the `ContextSpecific` object has value `None`.
///
/// ```rust,no_run
/// # #[macro_use] extern crate nom;
/// # #[macro_use] extern crate rusticata_macros;
/// # #[macro_use] extern crate der_parser;
/// use der_parser::*;
/// use nom::{IResult,Err,ErrorKind};
///
/// # fn main() {
/// let empty = &b""[..];
/// let bytes1 = [ 0x30, 0x0a,
///                0x0a, 0x03, 0x00, 0x00, 0x01,
///                0x02, 0x03, 0x01, 0x00, 0x01];
/// let bytes2 = [ 0x30, 0x05,
///                0x02, 0x03, 0x01, 0x00, 0x01];
/// let expected1  = DerObject::from_obj(DerObjectContent::Sequence(vec![
///     DerObject::from_obj(
///         DerObjectContent::ContextSpecific(0,
///             Some(Box::new(DerObject::from_obj(DerObjectContent::Enum(1)))))
///     ),
///     DerObject::from_int_slice(b"\x01\x00\x01"),
/// ]));
/// let expected2  = DerObject::from_obj(DerObjectContent::Sequence(vec![
///     DerObject::from_obj(
///         DerObjectContent::ContextSpecific(0, None),
///     ),
///     DerObject::from_int_slice(b"\x01\x00\x01"),
/// ]));
///
/// fn parse_optional_enum(i:&[u8]) -> IResult<&[u8],DerObject> {
///     parse_der_optional!(i, parse_der_enum)
/// }
/// fn parser(i:&[u8]) -> IResult<&[u8],DerObject> {
///     parse_der_sequence_defined!(i,
///         parse_optional_enum,
///         parse_der_integer
///     )
/// };
///
/// assert_eq!(parser(&bytes1), IResult::Done(empty, expected1));
/// assert_eq!(parser(&bytes2), IResult::Done(empty, expected2));
/// # }
/// ```
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

/// Parse a constructed DER element
///
/// Read a constructed DER element (sequence or set, typically) using the provided functions.
/// This is generally used to build a struct from a DER sequence.
///
/// The returned object is a tuple containing a [`DerObjectHeader`](struct.DerObjectHeader.html)
/// and the object returned by the subparser.
///
/// To ensure the subparser consumes all bytes from the constructed object, add the `eof!()`
/// subparser as the last parsing item.
///
/// To verify the tag of the constructed element, use the `TAG` version, for ex
/// `parse_der_struct!(i, TAG DerTag::Sequence, parse_der_integer)`
///
/// Similar to [`parse_der_sequence_defined`](macro.parse_der_sequence_defined.html), but using the
/// `do_parse` macro from nom.
/// This allows declaring variables, and running code at the end.
///
/// # Examples
///
/// Basic struct parsing (ignoring tag):
///
/// ```rust,no_run
/// # #[macro_use] extern crate nom;
/// # #[macro_use] extern crate rusticata_macros;
/// # #[macro_use] extern crate der_parser;
/// use der_parser::*;
/// use nom::{IResult,Err,ErrorKind};
///
/// # fn main() {
/// #[derive(Debug, PartialEq)]
/// struct MyStruct<'a>{
///     a: DerObject<'a>,
///     b: DerObject<'a>,
/// }
///
/// fn parse_struct01(i: &[u8]) -> IResult<&[u8],(DerObjectHeader,MyStruct)> {
///     parse_der_struct!(
///         i,
///         a: parse_der_integer >>
///         b: parse_der_integer >>
///            eof!() >>
///         ( MyStruct{ a: a, b: b } )
///     )
/// }
///
/// let bytes = [ 0x30, 0x0a,
///               0x02, 0x03, 0x01, 0x00, 0x01,
///               0x02, 0x03, 0x01, 0x00, 0x00,
/// ];
/// let empty = &b""[..];
/// let expected = (
///     DerObjectHeader{
///         class: 0,
///         structured: 1,
///         tag: 0x10,
///         len: 0xa,
///     },
///     MyStruct {
///         a: DerObject::from_int_slice(b"\x01\x00\x01"),
///         b: DerObject::from_int_slice(b"\x01\x00\x00"),
///     }
/// );
/// let res = parse_struct01(&bytes);
/// assert_eq!(res, IResult::Done(empty, expected));
/// # }
/// ```
///
/// To check the expected tag, use the `TAG <tagname>` variant:
///
/// ```rust,no_run
/// # #[macro_use] extern crate nom;
/// # #[macro_use] extern crate der_parser;
/// # use der_parser::*;
/// # use nom::{IResult,Err,ErrorKind};
/// # fn main() {
/// struct MyStruct<'a>{
///     a: DerObject<'a>,
///     b: DerObject<'a>,
/// }
///
/// fn parse_struct_with_tag(i: &[u8]) -> IResult<&[u8],(DerObjectHeader,MyStruct)> {
///     parse_der_struct!(
///         i,
///         TAG DerTag::Sequence,
///         a: parse_der_integer >>
///         b: parse_der_integer >>
///            eof!() >>
///         ( MyStruct{ a: a, b: b } )
///     )
/// }
/// # }
/// ```
#[macro_export]
macro_rules! parse_der_struct(
    ($i:expr, TAG $tag:expr, $($rest:tt)*) => ({
        use $crate::{DerObjectHeader,der_read_element_header};
        do_parse!(
            $i,
            hdr: verify!(der_read_element_header, |ref hdr: DerObjectHeader|
                         hdr.structured == 1 && hdr.tag == $tag as u8) >>
            res: flat_take!(hdr.len as usize, do_parse!( $($rest)* )) >>
            (hdr,res)
        )
    });
    ($i:expr, $($rest:tt)*) => ({
        use $crate::{DerObjectHeader,der_read_element_header};
        do_parse!(
            $i,
            hdr: verify!(der_read_element_header, |ref hdr: DerObjectHeader| hdr.structured == 1) >>
            res: flat_take!(hdr.len as usize, do_parse!( $($rest)* )) >>
            (hdr,res)
        )
    });
);

/// Parse a tagged DER element
///
/// Read a tagged DER element using the provided function.
///
/// The returned object is either the object returned by the subparser, or a nom error.
/// Unlike [`parse_der_explicit`](fn.parse_der_explicit.html) or
/// [`parse_der_implicit`](fn.parse_der_implicit.html), the returned values are *not* encapsulated
/// in a `DerObject` (they are directly returned, without the tag).
///
/// To specify the kind of tag, use the EXPLICIT or IMPLICIT keyword. If no keyword is specified,
/// the parsing is EXPLICIT by default.
///
/// When parsing IMPLICIT values, the third argument is a [`DerTag`](enum.DerTag.html) defining the
/// subtype of the object.
///
/// # Examples
///
/// The following parses `[2] INTEGER`:
///
/// ```rust,no_run
/// # #[macro_use] extern crate nom;
/// # #[macro_use] extern crate rusticata_macros;
/// # #[macro_use] extern crate der_parser;
/// use der_parser::*;
/// use nom::{IResult,Err,ErrorKind};
///
/// # fn main() {
/// fn parse_int_explicit(i:&[u8]) -> IResult<&[u8],u32> {
///     map_res!(
///         i,
///         parse_der_tagged!(EXPLICIT 2, parse_der_integer),
///         |x: DerObject| x.as_u32()
///     )
/// }
/// let bytes = &[0xa2, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01];
/// let res = parse_int_explicit(bytes);
/// match res {
///     IResult::Done(rem,val) => {
///         assert!(rem.is_empty());
///         assert_eq!(val, 0x10001);
///     },
///     _ => assert!(false)
/// }
/// # }
/// ```
///
/// The following parses `[2] IMPLICIT INTEGER`:
///
/// ```rust,no_run
/// # #[macro_use] extern crate nom;
/// # #[macro_use] extern crate rusticata_macros;
/// # #[macro_use] extern crate der_parser;
/// use der_parser::*;
/// use nom::{IResult,Err,ErrorKind};
///
/// # fn main() {
/// fn parse_int_implicit(i:&[u8]) -> IResult<&[u8],u32> {
///     map_res!(
///         i,
///         parse_der_tagged!(IMPLICIT 2, DerTag::Integer),
///         |x: DerObject| x.as_u32()
///     )
/// }
/// let bytes = &[0xa2, 0x03, 0x01, 0x00, 0x01];
/// let res = parse_int_implicit(bytes);
/// match res {
///     IResult::Done(rem,val) => {
///         assert!(rem.is_empty());
///         assert_eq!(val, 0x10001);
///     },
///     _ => assert!(false)
/// }
/// # }
/// ```
#[macro_export]
macro_rules! parse_der_tagged(
    ($i:expr, EXPLICIT $tag:expr, $f:ident) => ({
        use $crate::{DerObjectHeader,der_read_element_header};
        do_parse!(
            $i,
            hdr: verify!(der_read_element_header, |ref hdr: DerObjectHeader| hdr.tag == $tag) >>
            res: flat_take!(hdr.len as usize, call!( $f )) >>
            (res)
        )
    });
    ($i:expr, EXPLICIT $tag:expr, $submac:ident!( $($args:tt)*)) => ({
        use $crate::{DerObjectHeader,der_read_element_header};
        do_parse!(
            $i,
            hdr: verify!(der_read_element_header, |ref hdr: DerObjectHeader| hdr.tag == $tag) >>
            res: flat_take!(hdr.len as usize, $submac!( $($args)* )) >>
            (res)
        )
    });
    ($i:expr, IMPLICIT $tag:expr, $type:expr) => ({
        use $crate::{DerObjectHeader,der_read_element_header,der_read_element_content_as};
        do_parse!(
            $i,
            hdr: verify!(der_read_element_header, |ref hdr: DerObjectHeader| hdr.tag == $tag) >>
            res: call!(der_read_element_content_as, $type as u8, hdr.len as usize) >>
            (DerObject::from_obj(res))
        )
    });
    ($i:expr, $tag:expr, $f:ident) => ( parse_der_tagged!($i, EXPLICIT $tag, $f) );
);

/// Parse an application DER element
///
/// Read an application DER element using the provided functions.
/// This is generally used to build a struct from a DER sequence.
///
/// The returned object is a tuple containing a [`DerObjectHeader`](struct.DerObjectHeader.html)
/// and the object returned by the subparser.
///
/// To ensure the subparser consumes all bytes from the constructed object, add the `eof!()`
/// subparser as the last parsing item.
///
/// # Examples
///
/// The following parses `[APPLICATION 2] INTEGER`:
///
/// ```rust,no_run
/// # #[macro_use] extern crate nom;
/// # #[macro_use] extern crate rusticata_macros;
/// # #[macro_use] extern crate der_parser;
/// use der_parser::*;
/// use nom::{IResult,Err,ErrorKind};
///
/// # fn main() {
/// #[derive(Debug, PartialEq)]
/// struct SimpleStruct {
///     a: u32,
/// };
/// fn parse_app01(i:&[u8]) -> IResult<&[u8],(DerObjectHeader,SimpleStruct)> {
///     parse_der_application!(
///         i,
///         APPLICATION 2,
///         a: map_res!(parse_der_integer,|x: DerObject| x.as_u32()) >>
///            eof!() >>
///         ( SimpleStruct{ a:a } )
///     )
/// }
/// let bytes = &[0x62, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01];
/// let res = parse_app01(bytes);
/// match res {
///     IResult::Done(rem,(hdr,app)) => {
///         assert!(rem.is_empty());
///         assert_eq!(hdr.tag, 2);
///         assert!(hdr.is_application());
///         assert_eq!(hdr.structured, 1);
///         assert_eq!(app, SimpleStruct{ a:0x10001 });
///     },
///     _ => assert!(false)
/// }
/// # }
/// ```
#[macro_export]
macro_rules! parse_der_application(
    ($i:expr, APPLICATION $tag:expr, $($rest:tt)*) => ({
        use $crate::{DerObjectHeader,der_read_element_header};
        do_parse!(
            $i,
            hdr: verify!(der_read_element_header, |ref hdr: DerObjectHeader|
                         hdr.class == 0b01 && hdr.tag == $tag) >>
            res: flat_take!(hdr.len as usize, do_parse!( $($rest)* )) >>
            (hdr,res)
        )
    });
    ($i:expr, $tag:expr, $($rest:tt)*) => ( parse_der_application!($i, $tag, $($rest)*) );
);
