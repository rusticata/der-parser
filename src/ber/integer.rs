use crate::error::*;

pub(crate) fn decode_array_uint8(mut bytes: &[u8]) -> Result<u64, BerError> {
    // Check if MSB is set *before* leading zeroes
    if is_highest_bit_set(bytes) {
        return Err(BerError::IntegerNegative);
    }

    if bytes.len() > 9 {
        return Err(BerError::IntegerTooLarge);
    } else if bytes.len() == 9 {
        if bytes[0] != 0 {
            return Err(BerError::IntegerTooLarge);
        }
        bytes = &bytes[1..];
    }

    // Input has leading zeroes removed, so we need to add them back
    let mut output = [0u8; 8];
    output[8_usize.saturating_sub(bytes.len())..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(output))
}

pub(crate) fn decode_array_uint4(mut bytes: &[u8]) -> Result<u32, BerError> {
    // Check if MSB is set *before* leading zeroes
    if is_highest_bit_set(bytes) {
        return Err(BerError::IntegerNegative);
    }

    if bytes.len() > 5 {
        return Err(BerError::IntegerTooLarge);
    } else if bytes.len() == 5 {
        if bytes[0] != 0 {
            return Err(BerError::IntegerTooLarge);
        }
        bytes = &bytes[1..];
    }

    // Input has leading zeroes removed, so we need to add them back
    let mut output = [0u8; 4];
    output[4_usize.saturating_sub(bytes.len())..].copy_from_slice(bytes);
    Ok(u32::from_be_bytes(output))
}

pub(crate) fn decode_array_int8(input: &[u8]) -> Result<i64, BerError> {
    let i_len = input.len();
    if i_len > 8 {
        return Err(BerError::IntegerTooLarge);
    }

    let mut output = [0x00u8; 8];
    output[..i_len].copy_from_slice(input);

    let result = i64::from_be_bytes(output);

    Ok(result.wrapping_shr((8_u32 - (i_len as u32)) << 3))
}

pub(crate) fn decode_array_int4(input: &[u8]) -> Result<i32, BerError> {
    let i_len = input.len();
    if i_len > 4 {
        return Err(BerError::IntegerTooLarge);
    }

    let mut output = [0x00u8; 4];
    output[..i_len].copy_from_slice(input);

    let result = i32::from_be_bytes(output);

    Ok(result.wrapping_shr((4_u32 - (i_len as u32)) << 3))
}

/// Is the highest bit of the first byte in the slice 1? (if present)
#[inline]
pub(crate) fn is_highest_bit_set(bytes: &[u8]) -> bool {
    bytes
        .get(0)
        .map(|byte| byte & 0b10000000 != 0)
        .unwrap_or(false)
}
