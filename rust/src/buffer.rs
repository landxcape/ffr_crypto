use std::ffi::CString;
use std::os::raw::c_char;

use crate::status::{ERROR_INVALID_INPUT, SUCCESS};

/// Releases a string allocated by this library.
///
/// # Safety
/// `ptr` must be null or a live pointer returned by this library from
/// `CString::into_raw`, and it must not have been released previously.
#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

/// Releases a byte buffer allocated by this library.
///
/// # Safety
/// `ptr` must be null or a live byte buffer returned by this library, `len`
/// must be its exact length, and the buffer must not have been released before.
#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

pub(crate) unsafe fn write_output(bytes: Vec<u8>, out: *mut *mut u8, out_len: *mut usize) -> i32 {
    if out.is_null() || out_len.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let len = bytes.len();
    let mut bytes = bytes.into_boxed_slice();
    *out = bytes.as_mut_ptr();
    *out_len = len;
    std::mem::forget(bytes);
    SUCCESS
}
