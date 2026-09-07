pub mod converse;
pub mod session;

use thiserror::Error as ThisError;

use elevate_pam::constants::*;

#[derive(Debug, ThisError)]
pub enum PamError {
    #[error("{0}")]
    Error(String),
    #[error("{0}")]
    AuthError(String),
    #[error("new auth token required: {0}")]
    NewAuthTokenRequired(String),
    #[error("abort error: {0}")]
    AbortError(String),
}

impl PamError {
    /// Classify a raw elevate-pam status code the same way greetd's own
    /// code used to classify `pam_sys::PamReturnCode` -- same match arms,
    /// just against elevate-pam's `PAM_*` i32 constants instead of that
    /// crate's enum.
    pub fn from_code(prefix: &str, code: i32) -> PamError {
        match code {
            PAM_ABORT => PamError::AbortError(format!("{prefix}: {code}")),
            PAM_AUTH_ERR
            | PAM_MAXTRIES
            | PAM_CRED_EXPIRED
            | PAM_ACCT_EXPIRED
            | PAM_CRED_INSUFFICIENT
            | PAM_USER_UNKNOWN
            | PAM_PERM_DENIED
            | PAM_SERVICE_ERR => PamError::AuthError(format!("{prefix}: {code}")),
            PAM_NEW_AUTHTOK_REQD => PamError::NewAuthTokenRequired(format!("{prefix}: {code}")),
            _ => PamError::Error(format!("{prefix}: {code}")),
        }
    }

    /// Same as [`Self::from_code`], from an [`elevate_pam::PamError`].
    pub fn from_elevate(prefix: &str, e: elevate_pam::PamError) -> PamError {
        Self::from_code(prefix, e.to_status().code())
    }
}
