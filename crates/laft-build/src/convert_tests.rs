//! Tests of recipe conversion.

use std::fs;
use std::path::Path;

use crate::recipe::FileRef;
use crate::repo::Repos;

/// Evaluates the package `zlib` of a fresh repository whose recipe is
/// `recipe`.
fn eval(dir: &Path, recipe: &str) -> Result<crate::Recipe, crate::Error> {
    let repo = dir.join("core");
    fs::create_dir_all(repo.join("recipes/zlib")).expect("the recipe directory is made");
    fs::write(repo.join("recipes.stav"), "recipe_repo core {}\n")
        .expect("the descriptor is written");
    fs::write(repo.join("recipes/zlib/package.stav"), recipe).expect("the recipe is written");
    let repos = Repos::open(&[repo]).expect("the repository is valid");
    let name = "zlib".parse().expect("a valid name");
    let evaluation = repos.evaluate(&name)?;
    Ok(evaluation.recipes[0].clone())
}

/// A declared recipe file maps to its sandbox path with the hash of its
/// content.
#[test]
fn a_recipe_file_maps_to_its_sandbox_path() {
    let dir = laft_test::tempdir();
    fs::create_dir_all(dir.path().join("core/recipes/zlib")).expect("the recipe directory is made");
    fs::write(
        dir.path().join("core/recipes/zlib/config"),
        b"kernel config",
    )
    .expect("the file is written");
    let recipe = eval(
        dir.path(),
        r#"package zlib {
  version = "1"
  summary = "Z"
  license = [MIT]
  empty = true
  build custom {}
  recipe_files = [./config]
}
"#,
    )
    .expect("the recipe is valid");
    assert_eq!(
        recipe.recipe_files,
        [FileRef {
            path: "/build/recipes/core/zlib/config".into(),
            blake3: laft_core::Blake3Hash::of(b"kernel config"),
        }]
    );
}

/// A declared recipe file that cannot be read is refused.
#[test]
fn a_recipe_file_that_cannot_be_read_is_refused() {
    let dir = laft_test::tempdir();
    let error = eval(
        dir.path(),
        r#"package zlib {
  version = "1"
  summary = "Z"
  license = [MIT]
  empty = true
  build custom {}
  recipe_files = [./config]
}
"#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("R006"), "{error}");
}

/// A declared recipe file outside the recipe directory and `common/` is
/// refused.
#[test]
fn a_recipe_file_outside_the_recipe_directories_is_refused() {
    let dir = laft_test::tempdir();
    let error = eval(
        dir.path(),
        r#"package zlib {
  version = "1"
  summary = "Z"
  license = [MIT]
  empty = true
  build custom {}
  recipe_files = [../other/config]
}
"#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("R002"), "{error}");
}
