use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use asl_types::error::AslError;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rustix::fs::{Mode, OFlags, fchmod};
use zeroize::{Zeroize, Zeroizing};

use super::filesystem::{ensure_private_directory, io_error, open_regular};

const KEY_MAGIC: [u8; 4] = *b"ASLK";
const SECRET_MAGIC: [u8; 4] = *b"ASLS";
const FORMAT_VERSION: u16 = 1;
const KEY_FILE: &str = "secret.key";
const KEY_FILE_LEN: usize = 4 + 2 + 32;
const NONCE_LEN: usize = 12;

pub fn protect_secret(plaintext: &[u8]) -> Result<Vec<u8>, AslError> {
    if plaintext.is_empty() {
        return Err(AslError::KeyProtectionFailed);
    }
    let key = load_or_create_key()?;
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| AslError::KeyProtectionFailed)?;
    let mut output = Vec::with_capacity(4 + 2 + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&SECRET_MAGIC);
    output.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn unprotect_secret(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, AslError> {
    const HEADER: usize = 4 + 2 + NONCE_LEN;
    if ciphertext.len() <= HEADER
        || ciphertext[..4] != SECRET_MAGIC
        || u16::from_le_bytes([ciphertext[4], ciphertext[5]]) != FORMAT_VERSION
    {
        return Err(AslError::KeyProtectionFailed);
    }
    let key = load_or_create_key()?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(&ciphertext[6..HEADER]);
    cipher
        .decrypt(nonce, &ciphertext[HEADER..])
        .map(Zeroizing::new)
        .map_err(|_| AslError::KeyProtectionFailed)
}

fn load_or_create_key() -> Result<Zeroizing<[u8; 32]>, AslError> {
    let directory = ensure_private_directory(&state_directory()?)?;
    let created = match open_regular(
        &directory,
        KEY_FILE,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
    ) {
        Ok(file) => {
            write_new_key(&file)?;
            true
        }
        Err(AslError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };
    let file = open_regular(
        &directory,
        KEY_FILE,
        if created {
            OFlags::RDONLY
        } else {
            OFlags::RDWR
        },
    )?;
    if !created {
        for _ in 0..50 {
            if file.metadata().map(|metadata| metadata.len()).ok() == Some(KEY_FILE_LEN as u64) {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
    secure_existing_key(&file)?;
    let key = read_key(&file)?;
    if created {
        directory.sync_all().map_err(io_error)?;
    }
    Ok(key)
}

fn write_new_key(file: &File) -> Result<(), AslError> {
    fchmod(file, Mode::RUSR | Mode::WUSR).map_err(io_error)?;
    let mut key = Zeroizing::new([0u8; 32]);
    random_bytes(key.as_mut())?;
    let mut bytes = [0u8; KEY_FILE_LEN];
    bytes[..4].copy_from_slice(&KEY_MAGIC);
    bytes[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[6..].copy_from_slice(key.as_ref());
    (&*file).write_all(&bytes)?;
    file.sync_all()?;
    bytes.zeroize();
    Ok(())
}

fn secure_existing_key(file: &File) -> Result<(), AslError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() != KEY_FILE_LEN as u64
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(AslError::KeyProtectionFailed);
    }
    fchmod(file, Mode::RUSR | Mode::WUSR).map_err(io_error)?;
    if file.metadata()?.mode() & 0o077 != 0 {
        return Err(AslError::KeyProtectionFailed);
    }
    Ok(())
}

fn read_key(file: &File) -> Result<Zeroizing<[u8; 32]>, AslError> {
    let mut bytes = Zeroizing::new([0u8; KEY_FILE_LEN]);
    (&*file).read_exact(bytes.as_mut())?;
    if bytes[..4] != KEY_MAGIC || u16::from_le_bytes([bytes[4], bytes[5]]) != FORMAT_VERSION {
        return Err(AslError::KeyProtectionFailed);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes[6..]);
    bytes.zeroize();
    Ok(key)
}

fn state_directory() -> Result<PathBuf, AslError> {
    let base = match env::var_os("XDG_STATE_HOME") {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(AslError::KeyProtectionFailed);
            }
            path
        }
        _ => {
            let home = env::var_os("HOME").ok_or(AslError::KeyProtectionFailed)?;
            let home = PathBuf::from(home);
            if !home.is_absolute() {
                return Err(AslError::KeyProtectionFailed);
            }
            home.join(".local").join("state")
        }
    };
    Ok(base.join("asl"))
}

fn random_bytes(output: &mut [u8]) -> Result<(), AslError> {
    let mut source = File::open(Path::new("/dev/urandom")).map_err(io_error)?;
    source.read_exact(output).map_err(io_error)?;
    Ok(())
}
