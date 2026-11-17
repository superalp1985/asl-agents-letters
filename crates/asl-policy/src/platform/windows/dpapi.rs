use std::{ffi::c_void, slice};

use asl_types::error::AslError;
use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    },
    core::PCWSTR,
};
use zeroize::{Zeroize, Zeroizing};

struct LocalBlob(CRYPT_INTEGER_BLOB);

impl Drop for LocalBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            unsafe {
                slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                let _ = LocalFree(Some(HLOCAL(self.0.pbData.cast::<c_void>())));
            }
        }
    }
}

pub fn protect_secret(plaintext: &[u8]) -> Result<Vec<u8>, AslError> {
    let input = input_blob(plaintext)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|_| AslError::KeyProtectionFailed)?;

    copy_output(output)
}

pub fn unprotect_secret(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, AslError> {
    let input = input_blob(ciphertext)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|_| AslError::KeyProtectionFailed)?;

    copy_output(output).map(Zeroizing::new)
}

fn input_blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, AslError> {
    let cb_data = u32::try_from(bytes.len()).map_err(|_| AslError::KeyProtectionFailed)?;
    if cb_data == 0 {
        return Err(AslError::KeyProtectionFailed);
    }

    Ok(CRYPT_INTEGER_BLOB {
        cbData: cb_data,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

fn copy_output(output: CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, AslError> {
    let output = LocalBlob(output);
    if output.0.pbData.is_null() || output.0.cbData == 0 {
        return Err(AslError::KeyProtectionFailed);
    }

    let bytes =
        unsafe { slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) }.to_vec();
    Ok(bytes)
}
