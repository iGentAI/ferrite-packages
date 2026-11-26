#![forbid(unsafe_code)]
//! Test harness crate root. It mounts the package source with `#[path]`,
//! which the code gate refuses in an application and which is why this file
//! is not part of the package.

#[path = "../src/mod.rs"]
pub mod regex_lite;

/// The package's long-line tests, again on a thread with a 256 KiB stack, no
/// larger than a small wasm stack: matching must not recurse per pattern
/// element or per character. The vendored tests run them on the test
/// runner's thread, since vendored source may not name `std::thread`.
#[cfg(test)]
mod small_stack {
    use crate::regex_lite::tests;

    fn on_a_small_stack(f: fn()) {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn long_literals_and_long_lines() {
        on_a_small_stack(tests::long_literals_and_long_lines_match_on_a_small_stack);
    }

    #[test]
    fn long_repetitions() {
        on_a_small_stack(tests::deep_patterns_are_refused_and_long_repetitions_match);
    }

    #[test]
    fn searches_past_a_bound() {
        on_a_small_stack(tests::a_search_past_a_bound_reports_it);
    }

    #[test]
    fn single_character_alternations() {
        on_a_small_stack(
            tests::single_character_alternations_repeat_without_a_frame_per_iteration,
        );
    }

    #[test]
    fn everyday_searches() {
        on_a_small_stack(tests::everyday_searches_finish_on_long_lines);
    }
}
