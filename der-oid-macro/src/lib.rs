use proc_macro::TokenStream;

fn encode_components(components: &[num_bigint::BigUint], relative: bool) -> Vec<u8> {
    use num_traits::cast::ToPrimitive;

    let mut enc = Vec::new();
    let mut dec = components;
    if !relative {
        if dec.len() < 2 {
            if dec.len() == 1 && dec[0] == 0u8.into() {
                return vec![0];
            }
            panic!("Need at least two components for non-relative oid");
        }
        if dec[0] >= 7u8.into() || dec[1] >= 40u8.into() {
            panic!("First components are too big");
        }
        enc.push(dec[0].to_u8().unwrap() * 40 + dec[1].to_u8().unwrap());
        dec = &dec[2..];
    }

    for int in dec.iter() {
        let mut bytes = int.to_bytes_be();
        if bytes[0] == 0 {
            enc.push(0u8);
            continue;
        }
        let total_bits = (8 - bytes[0].leading_zeros()) as usize + (bytes.len() - 1) * 8;
        let octects_needed = ((total_bits + 6) / 7).max(1);
        enc.resize_with(enc.len() + octects_needed, Default::default);

        let mut pos = enc.len() - 1;
        let mut extra = 0u8;
        let mut extra_size = 0u8;
        bytes.reverse();
        let mut bytes_stored = 0;
        for byte in bytes.into_iter() {
            if extra_size == 7 {
                // there a seven bits in extra
                enc[pos] = extra | (1 << 7);
                bytes_stored += 1;
                pos -= 1;
                extra = 0;
                extra_size = 0;
            }
            // make space for the extra bits
            enc[pos] = (byte << extra_size) | extra | (1 << 7);
            bytes_stored += 1;
            if pos > 0 {
                pos -= 1;
                extra_size += 1;
                extra = byte >> (8 - extra_size);
            }
        }
        let last = enc.len() - 1;
        if bytes_stored != octects_needed {
            let first = last + 1 - octects_needed;
            enc[first] = extra | (1 << 7);
        }
        enc[last] ^= 1 << 7;
    }
    enc
}

#[proc_macro]
pub fn encode_oid(input: TokenStream) -> TokenStream {
    let s = input.to_string();

    let (rem, relative) = if s.starts_with("rel ") {
        (&s[4..], true)
    } else {
        (s.as_ref(), false)
    };

    let ints: Vec<num_bigint::BigUint> = rem
        .split('.')
        .map(|segment| segment.trim())
        .map(|s| s.parse().unwrap())
        .collect();

    let enc = encode_components(&ints, relative);

    let mut s = String::with_capacity(2 + 6 * enc.len());
    s.push('[');
    for byte in enc.iter() {
        s.insert_str(s.len(), &format!("0x{:02x}, ", byte));
    }
    s.push(']');
    s.parse().unwrap()
}
