//! Tests of the recipe environment.

use crate::env::Budget;

use super::test_support::recipe;

#[test]
fn a_parallel_recipe_joins_the_jobserver() {
    let budget = Budget {
        jobs: 12,
        share: 4,
        jobserver: true,
    };
    let env = recipe("pkg").environment(budget);
    assert_eq!(env.get(crate::env::JOBS).map(String::as_str), Some("4"));
    assert_eq!(
        env.get(crate::env::MAKEFLAGS).map(String::as_str),
        Some("-j12 --jobserver-auth=fifo:/build/jobserver")
    );
}

#[test]
fn a_parallel_recipe_without_a_jobserver_names_only_its_budget() {
    let budget = Budget {
        jobs: 12,
        share: 12,
        jobserver: false,
    };
    let env = recipe("pkg").environment(budget);
    assert_eq!(env.get(crate::env::JOBS).map(String::as_str), Some("12"));
    assert_eq!(
        env.get(crate::env::MAKEFLAGS).map(String::as_str),
        Some("-j12")
    );
}

#[test]
fn a_recipe_that_does_not_build_in_parallel_gets_one_job() {
    let mut r = recipe("pkg");
    r.options.parallel = false;
    let budget = Budget {
        jobs: 12,
        share: 4,
        jobserver: true,
    };
    let env = r.environment(budget);
    assert_eq!(env.get(crate::env::JOBS).map(String::as_str), Some("1"));
    assert_eq!(
        env.get(crate::env::MAKEFLAGS).map(String::as_str),
        Some("-j1")
    );
}

/// A recipe without `recipe_files` keeps the plan hash it had before the
/// field existed, so packages that declare none keep their store ids.
#[test]
fn a_recipe_without_recipe_files_keeps_its_plan_hash() {
    assert_eq!(
        recipe("zlib").plan_hash().to_string(),
        "b3:lw33unauo55ly2yqmakqyw6nfcvn5symd57xevk632vjya4mmqoa"
    );
}

/// A recipe without `check_user` keeps the plan hash it had before the
/// switch existed, so packages that do not opt in keep their store ids.
#[test]
fn a_recipe_without_check_user_keeps_its_plan_hash() {
    assert_eq!(
        recipe("zlib").plan_hash().to_string(),
        "b3:lw33unauo55ly2yqmakqyw6nfcvn5symd57xevk632vjya4mmqoa"
    );
}
