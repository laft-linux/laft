use std::path::PathBuf;

use crate::check_user::{CheckUserEnv, check_user_available};

/// An environment of a caller that is not root and has everything the
/// check user needs.
fn complete() -> CheckUserEnv {
    CheckUserEnv {
        root: false,
        user: Some("guest".to_owned()),
        newuidmap: Some(PathBuf::from("/usr/sbin/newuidmap")),
        newgidmap: Some(PathBuf::from("/usr/sbin/newgidmap")),
        subuid: "guest:100000:65536\n".to_owned(),
        subgid: "guest:100000:65536\n".to_owned(),
    }
}

#[test]
fn a_root_caller_needs_nothing() {
    let env = CheckUserEnv {
        root: true,
        user: None,
        newuidmap: None,
        newgidmap: None,
        subuid: String::new(),
        subgid: String::new(),
    };
    check_user_available(&env).expect("root maps the check user itself");
}

#[test]
fn a_caller_without_the_helpers_is_refused() {
    let env = CheckUserEnv {
        newuidmap: None,
        ..complete()
    };
    let reason = check_user_available(&env).unwrap_err().reason;
    assert!(reason.contains("newuidmap"), "{reason}");
    let env = CheckUserEnv {
        newgidmap: None,
        ..complete()
    };
    let reason = check_user_available(&env).unwrap_err().reason;
    assert!(reason.contains("newgidmap"), "{reason}");
}

#[test]
fn a_caller_without_a_subordinate_id_is_refused() {
    let env = CheckUserEnv {
        subuid: String::new(),
        ..complete()
    };
    let reason = check_user_available(&env).unwrap_err().reason;
    assert!(reason.contains("/etc/subuid"), "{reason}");
    let env = CheckUserEnv {
        subgid: "other:100000:65536\n".to_owned(),
        ..complete()
    };
    let reason = check_user_available(&env).unwrap_err().reason;
    assert!(reason.contains("/etc/subgid"), "{reason}");
}

#[test]
fn a_caller_without_a_name_is_refused() {
    let env = CheckUserEnv {
        user: None,
        ..complete()
    };
    let reason = check_user_available(&env).unwrap_err().reason;
    assert!(reason.contains("passwd"), "{reason}");
}

#[test]
fn the_first_entry_of_the_caller_counts() {
    let env = CheckUserEnv {
        subuid: "other:1:1\nguest:200000:65536\n".to_owned(),
        subgid: "other:1:1\nguest:200000:65536\n".to_owned(),
        ..complete()
    };
    check_user_available(&env).expect("the second entry is the caller's");
}
