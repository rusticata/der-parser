/// Internal OID arrays concatenation.
#[doc(hidden)]
#[macro_export]
macro_rules! array_concat(
    ($first:expr, $second:expr) => {
        &{
            let mut x = [0; $first.len() + 1 + $second.len()];

            let mut i = 0;
            while i < $first.len() {
                x[i] = $first[i];
                i += 1;
            }

            x[$first.len()] = $second[0] / 40;
            x[$first.len() + 1] = $second[0] % 40;
            let start = $first.len() + 1;

            let mut i = 1;
            while i < $second.len() {
                x[start + i] = $second[i];
                i += 1;
            }

            x
        }
    };
);

/// Create OID from two others.
#[macro_export]
macro_rules! oid_append(
    // oid_append!(A, B)
    ($parent:ident, $appendix:ident) => ({
        const CONCATENATED: &[u8] = der_parser::array_concat!(
            &$parent.bytes_from_borrowed(),
            &$appendix.bytes_from_borrowed()
        );
        Oid::new(std::borrow::Cow::Borrowed(CONCATENATED))
    });

    // oid_append!(A, 3.4)
    ($parent:expr, $appendix_start:tt$(.$appendix_item:tt)*) => ({
        const PARENT: Oid = $parent;
        const APPENDIX: Oid = oid!($appendix_start$(.$appendix_item)*);
        oid_append!(PARENT, APPENDIX)
    });

    // oid_append!(oid!(1.2), oid!(3.4))
    ($parent:expr, $appendix:expr) => ({
        const PARENT: Oid = $parent;
        const APPENDIX: Oid = $appendix;
        oid_append!(PARENT, APPENDIX)
    });
);

#[cfg(test)]
mod tests {
    use crate::oid;
    use crate::oid::Oid;
    // oid!() macro used crate as `der_parser`
    use crate as der_parser;

    const A: Oid = oid!(1.2.3);
    const B: Oid = oid_append!(A, 4.5);
    const C: Oid = oid_append!(A, B);
    const D: Oid = oid_append!(C, C);

    #[test]
    #[rustfmt::skip]
    fn test_oid_inheritance() {
        assert_eq!(B, oid!(1.2.3.4.5));
        assert_eq!(C, oid!(1.2.3.1.2.3.4.5));
        assert_eq!(D, oid!(1.2.3.1.2.3.4.5.1.2.3.1.2.3.4.5));
    }

    const E: Oid = oid_append!(oid!(1.2.3), oid!(3.0));
    const F: Oid = oid_append!(oid!(0.0.3), oid!(0.3.0));
    const G: Oid = oid_append!(oid!(3.7.32452), oid!(2.29.34536));

    #[test]
    #[rustfmt::skip]
    fn test_oid_correct_concatenated() {
        assert_eq!(E, oid!(1.2.3.3.0));
        assert_eq!(F, oid!(0.0.3.0.3.0));
        assert_eq!(G, oid!(3.7.32452.2.29.34536));
    }
}
