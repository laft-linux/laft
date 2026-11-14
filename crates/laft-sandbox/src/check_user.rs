//! Whether the check user of a build sandbox can be mapped, and what the
//! host provides for it.

use std::env;
use std::fmt;
use std::fs;
use std::path::PathBuf;

use rustix::process::getuid;

/// What this caller and this host provide for mapping the check user.
///
/// [`check_user_env`] gathers it from the host. Tests inject their own.
#[derive(Debug, Clone, Default)]
pub struct CheckUserEnv {
    /// Whether the caller is root, which can map any ids itself.
    pub root: bool,
    /// The name of the caller, from `/etc/passwd`.
    pub user: Option<String>,
    /// The path of `newuidmap` on the path, if there is one.
    pub newuidmap: Option<PathBuf>,
    /// The path of `newgidmap` on the path, if there is one.
    pub newgidmap: Option<PathBuf>,
    /// The contents of `/etc/subuid`.
    pub subuid: String,
    /// The contents of `/etc/subgid`.
    pub subgid: String,
}

/// Why the check user cannot be mapped for this caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    /// What is missing, such as `newuidmap is not on the path`.
    pub reason: String,
}

impl Unavailable {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

/// Gathers what this caller and this host provide for mapping the check
/// user, for [`check_user_available`].
pub fn check_user_env() -> CheckUserEnv {
    let uid = getuid();
    CheckUserEnv {
        root: uid.is_root(),
        user: user_name(uid.as_raw()),
        newuidmap: find_tool("newuidmap"),
        newgidmap: find_tool("newgidmap"),
        subuid: fs::read_to_string("/etc/subuid").unwrap_or_default(),
        subgid: fs::read_to_string("/etc/subgid").unwrap_or_default(),
    }
}

/// Whether this caller can run a command as the check user.
///
/// A root caller always can: it writes the map of the new user namespace
/// itself. A caller that is not root maps the check user through
/// `newuidmap` and `newgidmap`, which the kernel lets write the ids of a
/// subordinate range of the caller, so the caller needs both helpers on
/// its path and a range of each kind of its own.
///
/// # Errors
///
/// Returns the first reason this caller cannot map the check user.
pub fn check_user_available(env: &CheckUserEnv) -> Result<(), Unavailable> {
    if env.root {
        return Ok(());
    }
    if env.newuidmap.is_none() {
        return Err(Unavailable::new("newuidmap is not on the path"));
    }
    if env.newgidmap.is_none() {
        return Err(Unavailable::new("newgidmap is not on the path"));
    }
    let Some(user) = env.user.as_deref() else {
        return Err(Unavailable::new(
            "the caller has no /etc/passwd entry, so its subordinate ids cannot be found",
        ));
    };
    if first_subordinate(&env.subuid, user).is_none() {
        return Err(Unavailable::new(format!(
            "no subordinate uid range for {user} in /etc/subuid"
        )));
    }
    if first_subordinate(&env.subgid, user).is_none() {
        return Err(Unavailable::new(format!(
            "no subordinate gid range for {user} in /etc/subgid"
        )));
    }
    Ok(())
}

/// The start of the first subordinate id range of `user` in `content`,
/// which is the contents of `/etc/subuid` or `/etc/subgid`.
pub(crate) fn first_subordinate(content: &str, user: &str) -> Option<u32> {
    content.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let start = fields.next()?.parse().ok()?;
        fields.next()?;
        (name == user).then_some(start)
    })
}

/// The name of the user `uid`, from the first `/etc/passwd` entry that
/// names it.
fn user_name(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        fields.next()?;
        let entry = fields.next()?;
        (entry == uid.to_string()).then(|| name.to_owned())
    })
}

/// The path of the tool `name` on the path, or `None` when the path has
/// no file of that name.
fn find_tool(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}

#[cfg(test)]
#[path = "check_user_tests.rs"]
mod tests;
