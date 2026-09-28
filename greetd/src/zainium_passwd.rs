//! `nix::unistd::User::from_name()` goes through libc's own `getpwnam()`,
//! which internally opens the literal `/etc/passwd` -- musl's internal
//! file opens don't route through the public, dynamically interposable
//! `open()` symbol at all, so even LD_PRELOAD-based path remapping (which
//! works fine for greetd's *own* file reads elsewhere in this fork) can't
//! fix this. Parse the real Zainium passwd file directly instead,
//! bypassing libc's NSS lookup entirely.

use std::ffi::CString;
use std::fs;
use std::path::PathBuf;

use nix::unistd::{Gid, Uid, User};

/// Look up a user by name, reading the real Zainium passwd file directly
/// (falling back to the plain FHS path for portability on a real FHS
/// host) instead of going through libc's own `getpwnam()`.
pub fn user_from_name(name: &str) -> std::io::Result<Option<User>> {
    let text = fs::read_to_string("/overlayer/syshub/etc/passwd")
        .or_else(|_| fs::read_to_string("/etc/passwd"))?;
    for line in text.lines() {
        let fields: Vec<&str> = line.splitn(7, ':').collect();
        if fields.len() < 7 || fields[0] != name {
            continue;
        }
        let (Ok(uid), Ok(gid)) = (fields[2].parse::<u32>(), fields[3].parse::<u32>()) else {
            continue;
        };
        return Ok(Some(User {
            name: fields[0].to_string(),
            passwd: CString::new(fields[1]).unwrap_or_default(),
            uid: Uid::from_raw(uid),
            gid: Gid::from_raw(gid),
            gecos: CString::new(fields[4]).unwrap_or_default(),
            dir: PathBuf::from(fields[5]),
            shell: PathBuf::from(fields[6]),
        }));
    }
    Ok(None)
}

/// Every gid `name` belongs to (their own primary gid plus every group
/// that lists them as a member), reading the real Zainium group file
/// directly instead of `initgroups()` -- that goes through the same
/// non-interposable musl-internal `/etc/group` access as `getpwnam()`.
pub fn groups_for_user(name: &str, primary_gid: u32) -> std::io::Result<Vec<Gid>> {
    let text = fs::read_to_string("/overlayer/syshub/etc/group")
        .or_else(|_| fs::read_to_string("/etc/group"))?;
    let mut gids = vec![Gid::from_raw(primary_gid)];
    for line in text.lines() {
        let f: Vec<&str> = line.splitn(4, ':').collect();
        if f.len() < 4 {
            continue;
        }
        let Ok(gid) = f[2].parse::<u32>() else {
            continue;
        };
        if gid == primary_gid {
            continue;
        }
        if f[3].split(',').any(|m| m == name) {
            gids.push(Gid::from_raw(gid));
        }
    }
    Ok(gids)
}
