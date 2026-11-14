//! Comparing build roots: the packages whose store ids differ.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use laft_core::StoreId;
use laft_pkg::Identity;
use laft_store::Store;

use crate::error::{BuildError, io};

/// One package that the stores of two build roots do not agree on, with
/// the store id of each root that holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreDifference {
    /// The package, from the metadata of its store entries, never from
    /// their directory names.
    pub identity: Identity,
    /// The store id of the first root, when it holds the package.
    pub first: Option<StoreId>,
    /// The store id of the second root, when it holds the package.
    pub second: Option<StoreId>,
}

/// Lists the packages whose store ids differ between the build roots
/// `first` and `second`, sorted by name, then variant. A package that only
/// one root holds, and one that both hold with different store ids, is
/// listed; roots that agree on a package list nothing. When a root holds
/// several entries of one package, the last one in the sorted listing, the
/// one with the greatest store id, counts.
///
/// # Errors
///
/// Fails when a root has no readable store directory, the store cannot be
/// listed, or an entry has no readable manifest or metadata.
pub fn compare_roots(first: &Path, second: &Path) -> Result<Vec<StoreDifference>, BuildError> {
    let (first, second) = (entries(first)?, entries(second)?);
    let identities: BTreeSet<&Identity> = first.keys().chain(second.keys()).collect();
    let mut out = Vec::new();
    for identity in identities {
        let (a, b) = (first.get(identity), second.get(identity));
        if a == b {
            continue;
        }
        out.push(StoreDifference {
            identity: identity.clone(),
            first: a.cloned(),
            second: b.cloned(),
        });
    }
    out.sort_by(|x, y| {
        (
            &x.identity.name,
            x.identity.variant,
            &x.identity.version,
            x.identity.rev,
            x.identity.arch,
        )
            .cmp(&(
                &y.identity.name,
                y.identity.variant,
                &y.identity.version,
                y.identity.rev,
                y.identity.arch,
            ))
    });
    Ok(out)
}

/// The store id of every entry of the store below `root`, keyed by the
/// identity of its package, which the metadata of the entry names.
fn entries(root: &Path) -> Result<BTreeMap<Identity, StoreId>, BuildError> {
    let dir = root.join("store");
    let metadata = fs::metadata(&dir).map_err(io(&dir))?;
    if !metadata.is_dir() {
        return Err(io(&dir)(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a store directory",
        )));
    }
    let store = Store::at(&dir);
    let mut out = BTreeMap::new();
    for dir_name in store.list()? {
        let meta = store.meta(&dir_name)?;
        let id = store.manifest(&dir_name)?.store_id();
        out.insert(meta.identity(), id);
    }
    Ok(out)
}

#[cfg(test)]
#[path = "compare_tests.rs"]
mod tests;
