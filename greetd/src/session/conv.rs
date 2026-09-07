use super::worker::{AuthMessageType, ParentToSessionChild, SessionChildToParent};
use crate::pam::converse::Converse;

/// PAM conversation implementation that forwards questions over a socket.
///
/// Owns a duplicated socket fd (via `try_clone`) rather than borrowing one,
/// so this type has no lifetime parameter -- elevate-pam's app-facing
/// `pam_conv_from_converser` requires `Box<dyn Converser + 'static>` (the
/// raw C `PamConv` it builds carries no lifetime of its own), and this
/// avoids needing any `unsafe` lifetime extension to satisfy that.
pub struct SessionConv {
    sock: std::os::unix::net::UnixDatagram,
}

impl SessionConv {
    fn question(&self, msg: &str, style: AuthMessageType) -> Result<Option<String>, ()> {
        let mut data = [0; 10240];
        let msg = SessionChildToParent::PamMessage {
            style,
            msg: msg.to_string(),
        };
        msg.send(&self.sock)
            .map_err(|e| eprintln!("pam_conv: {e}"))?;

        let msg = ParentToSessionChild::recv(&self.sock, &mut data)
            .map_err(|e| eprintln!("pam_conv: {e}"))?;

        match msg {
            ParentToSessionChild::PamResponse { resp, .. } => Ok(resp),
            ParentToSessionChild::Cancel => Err(()),
            _ => Err(()),
        }
    }

    /// Create a new `SessionConv` handler from a borrowed socket, duplicating
    /// its fd so the result owns its own handle to the same underlying
    /// socket.
    pub fn new(sock: &std::os::unix::net::UnixDatagram) -> std::io::Result<SessionConv> {
        Ok(SessionConv {
            sock: sock.try_clone()?,
        })
    }
}

impl Converse for SessionConv {
    fn prompt_echo(&self, msg: &str) -> Result<String, ()> {
        match self.question(msg, AuthMessageType::Visible) {
            Ok(Some(response)) => Ok(response),
            _ => Err(()),
        }
    }
    fn prompt_blind(&self, msg: &str) -> Result<String, ()> {
        match self.question(msg, AuthMessageType::Secret) {
            Ok(Some(response)) => Ok(response),
            _ => Err(()),
        }
    }
    fn info(&self, msg: &str) -> Result<(), ()> {
        match self.question(msg, AuthMessageType::Info) {
            Ok(None) => Ok(()),
            _ => Err(()),
        }
    }
    fn error(&self, msg: &str) -> Result<(), ()> {
        match self.question(msg, AuthMessageType::Error) {
            Ok(None) => Ok(()),
            _ => Err(()),
        }
    }
}
