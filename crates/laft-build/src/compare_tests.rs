use super::*;
use crate::test_support::TestPkg;
use laft_store::Store;

/// A store below `root/store` that holds `packages`, each added from a
/// package file written into `dir`. An empty store is a directory with no
/// entries.
fn store_with(
    root: &std::path::Path,
    dir: &std::path::Path,
    packages: &[TestPkg<'_>],
) -> Vec<laft_core::StoreId> {
    let store = Store::at(root.join("store"));
    let ids = packages
        .iter()
        .map(|package| package.add(&store, dir))
        .collect::<Vec<_>>();
    if ids.is_empty() {
        std::fs::create_dir_all(root.join("store")).unwrap();
    }
    ids
}

#[test]
fn roots_with_the_same_packages_report_nothing() {
    let dir = laft_test::tempdir();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let (file, id) = TestPkg::new("zlib").write(dir.path());
    for root in [&a, &b] {
        Store::at(root.join("store"))
            .insert(&file, &id, &dir.path().join("tmp"))
            .unwrap();
    }
    assert!(compare_roots(&a, &b).unwrap().is_empty());
}

#[test]
fn a_package_with_differing_store_ids_is_listed_with_both() {
    let dir = laft_test::tempdir();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let first = TestPkg {
        files: &[("usr/share/zlib/one", b"one")],
        ..TestPkg::new("zlib")
    };
    let second = TestPkg {
        files: &[("usr/share/zlib/two", b"two")],
        ..TestPkg::new("zlib")
    };
    let ids = store_with(&a, dir.path(), &[first]);
    let other = store_with(&b, dir.path(), &[second]);
    let differences = compare_roots(&a, &b).unwrap();
    assert_eq!(differences.len(), 1, "{differences:?}");
    let difference = &differences[0];
    assert_eq!(difference.identity.name.to_string(), "zlib");
    assert_eq!(difference.identity.version.to_string(), "1.0");
    assert_eq!(difference.first, Some(ids[0]));
    assert_eq!(difference.second, Some(other[0]));
}

#[test]
fn a_package_of_one_root_only_is_listed_with_its_root() {
    let dir = laft_test::tempdir();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let ids = store_with(&a, dir.path(), &[TestPkg::new("zlib")]);
    store_with(&b, dir.path(), &[]);
    let differences = compare_roots(&a, &b).unwrap();
    assert_eq!(differences.len(), 1, "{differences:?}");
    assert_eq!(differences[0].identity.name.to_string(), "zlib");
    assert_eq!(differences[0].first, Some(ids[0]));
    assert_eq!(differences[0].second, None);
}

#[test]
fn differences_are_sorted_by_name_then_variant() {
    let dir = laft_test::tempdir();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let mut zlib = TestPkg::new("zlib");
    zlib.variant = laft_core::Variant::Static;
    store_with(
        &a,
        dir.path(),
        &[zlib, TestPkg::new("zlib"), TestPkg::new("xz")],
    );
    store_with(&b, dir.path(), &[]);
    let differences = compare_roots(&a, &b).unwrap();
    let names: Vec<String> = differences.iter().map(|d| d.identity.to_string()).collect();
    assert_eq!(names, ["xz-1.0-r1", "zlib-1.0-r1", "zlib-1.0-r1+static"]);
}

#[test]
fn a_root_without_a_store_directory_is_refused() {
    let dir = laft_test::tempdir();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let error = compare_roots(&a, &b).unwrap_err();
    assert!(matches!(error, BuildError::Io { .. }), "{error:?}");
    assert!(error.to_string().contains("store"), "{error}");
}
