use std::{ffi::CString, pin::Pin};

use elevate_pam::conv::{pam_conv_from_converser, Converser};
use elevate_pam::constants::*;
use elevate_pam::types::{ItemType, Message, MsgStyle, Response};
use elevate_pam::appl::PamBuilder;
use elevate_pam::PamHandle;

use super::{converse::Converse, PamError};

/// Bridges greetd's own per-message [`Converse`] trait to elevate-pam's
/// batch-style `Converser` trait -- lets `SessionConv` (talks to the
/// greeter over a socket) stay completely unchanged.
struct ConverseAdapter(Pin<Box<dyn Converse + Send>>);

impl Converser for ConverseAdapter {
    fn converse(&mut self, messages: &[Message]) -> elevate_pam::PamResult<Vec<Response>> {
        let mut out = Vec::with_capacity(messages.len());
        for m in messages {
            let text = match m.style {
                MsgStyle::PromptEchoOff => self
                    .0
                    .prompt_blind(&m.text)
                    .map_err(|_| elevate_pam::PamError::Status(PAM_CONV_ERR.into()))?,
                MsgStyle::PromptEchoOn => self
                    .0
                    .prompt_echo(&m.text)
                    .map_err(|_| elevate_pam::PamError::Status(PAM_CONV_ERR.into()))?,
                MsgStyle::ErrorMsg => {
                    self.0
                        .error(&m.text)
                        .map_err(|_| elevate_pam::PamError::Status(PAM_CONV_ERR.into()))?;
                    String::new()
                }
                MsgStyle::TextInfo => {
                    self.0
                        .info(&m.text)
                        .map_err(|_| elevate_pam::PamError::Status(PAM_CONV_ERR.into()))?;
                    String::new()
                }
                // Linux-PAM extensions greetd's own Converse trait has no
                // equivalent for (radio-button / raw binary prompts) --
                // no real PAM module used in this project issues these;
                // fail the conversation rather than silently drop data.
                MsgStyle::RadioType | MsgStyle::BinaryPrompt => {
                    return Err(elevate_pam::PamError::Status(PAM_CONV_ERR.into()));
                }
            };
            out.push(Response { text, retcode: 0 });
        }
        Ok(out)
    }
}

pub struct PamSession {
    // `Option` only so `end()` can `.take()` it out and consume it --
    // elevate-pam's `PamHandle::end` takes `self` by value, unlike
    // pam-sys's raw-pointer API this replaces.
    handle: Option<PamHandle>,
}

impl PamSession {
    pub fn start(
        service: &str,
        user: &str,
        pam_conv: Pin<Box<dyn Converse + Send>>,
    ) -> Result<PamSession, PamError> {
        let conv = pam_conv_from_converser(Box::new(ConverseAdapter(pam_conv)));
        match PamBuilder::new(service).user(user).start(conv) {
            Ok(handle) => Ok(PamSession {
                handle: Some(handle),
            }),
            Err(e) => Err(PamError::from_elevate("pam_start", e)),
        }
    }

    fn handle(&mut self) -> &mut PamHandle {
        self.handle.as_mut().expect("PamSession used after end()")
    }

    pub fn authenticate(&mut self, flags: i32) -> Result<(), PamError> {
        self.handle()
            .authenticate(flags)
            .map_err(|e| PamError::from_elevate("pam_authenticate", e))
    }

    pub fn change_auth_token(&mut self, flags: i32) -> Result<(), PamError> {
        self.handle()
            .chauthtok(flags)
            .map_err(|e| PamError::from_elevate("pam_chauthtok", e))
    }

    pub fn acct_mgmt(&mut self, flags: i32) -> Result<(), PamError> {
        self.handle()
            .acct_mgmt(flags)
            .map_err(|e| PamError::from_elevate("pam_acct_mgmt", e))
    }

    pub fn setcred(&mut self, flags: i32) -> Result<(), PamError> {
        self.handle()
            .setcred(flags)
            .map_err(|e| PamError::from_elevate("pam_setcred", e))
    }

    pub fn open_session(&mut self, flags: i32) -> Result<(), PamError> {
        self.handle()
            .open_session(flags)
            .map_err(|e| PamError::from_elevate("pam_open_session", e))
    }

    pub fn close_session(&mut self, flags: i32) -> Result<(), PamError> {
        self.handle()
            .close_session(flags)
            .map_err(|e| PamError::from_elevate("pam_close_session", e))
    }

    pub fn putenv(&mut self, v: &str) -> Result<(), PamError> {
        self.handle()
            .putenv(v)
            .map_err(|e| PamError::from_elevate("pam_putenv", e))
    }

    pub fn set_item_tty(&mut self, value: &str) -> Result<(), PamError> {
        self.handle()
            .set_item_str(ItemType::Tty, Some(value))
            .map_err(|e| PamError::from_elevate("pam_set_item", e))
    }

    pub fn get_user(&mut self) -> Result<String, PamError> {
        self.handle()
            .get_user(None)
            .map_err(|e| PamError::from_elevate("pam_get_user", e))
    }

    /// Full PAM-accumulated environment, as owned `CString`s ready for
    /// `nix::unistd::execve`'s `env` argument.
    pub fn getenvlist(&mut self) -> Result<Vec<CString>, PamError> {
        Ok(self
            .handle()
            .envlist()
            .iter()
            .filter_map(|s| CString::new(s.as_str()).ok())
            .collect())
    }

    pub fn end(mut self) -> Result<(), PamError> {
        let handle = self.handle.take().expect("PamSession used after end()");
        handle
            .end(PAM_SUCCESS)
            .map_err(|e| PamError::from_elevate("pam_end", e))
    }
}
