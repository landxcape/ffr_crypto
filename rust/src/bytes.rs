use subtle::ConstantTimeEq;

use crate::status::{ERROR_INVALID_INPUT, SUCCESS};

pub(crate) fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

/// Compares two caller-owned byte slices using constant-time equality when
/// their public lengths match.
///
/// # Safety
/// Nonempty input pointers must be readable for their corresponding lengths.
/// `out_equal` must be writable for one byte.
#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_constant_time_equals(
    left: *const u8,
    left_len: usize,
    right: *const u8,
    right_len: usize,
    out_equal: *mut u8,
) -> i32 {
    if out_equal.is_null()
        || (left.is_null() && left_len != 0)
        || (right.is_null() && right_len != 0)
    {
        return ERROR_INVALID_INPUT;
    }

    let left = if left_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(left, left_len)
    };
    let right = if right_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(right, right_len)
    };

    *out_equal = u8::from(constant_time_equals(left, right));
    SUCCESS
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use super::{constant_time_equals, ffr_crypto_constant_time_equals};
    use crate::status::{ERROR_INVALID_INPUT, SUCCESS};

    #[test]
    fn compares_equal_and_unequal_values() {
        assert!(constant_time_equals(b"same", b"same"));
        assert!(!constant_time_equals(b"same", b"diff"));
        assert!(!constant_time_equals(b"short", b"longer"));
        assert!(constant_time_equals(b"", b""));
    }

    #[test]
    fn ffi_validates_pointers_and_sets_output() {
        let mut equal = 0u8;
        unsafe {
            assert_eq!(
                ffr_crypto_constant_time_equals(ptr::null(), 0, ptr::null(), 0, &mut equal),
                SUCCESS
            );
            assert_eq!(equal, 1);
            assert_eq!(
                ffr_crypto_constant_time_equals(ptr::null(), 1, ptr::null(), 0, &mut equal),
                ERROR_INVALID_INPUT
            );
            assert_eq!(
                ffr_crypto_constant_time_equals(
                    b"same".as_ptr(),
                    4,
                    b"same".as_ptr(),
                    4,
                    ptr::null_mut(),
                ),
                ERROR_INVALID_INPUT
            );
            assert_eq!(
                ffr_crypto_constant_time_equals(
                    b"same".as_ptr(),
                    4,
                    b"diff".as_ptr(),
                    4,
                    &mut equal,
                ),
                SUCCESS
            );
            assert_eq!(equal, 0);
        }
    }
}
