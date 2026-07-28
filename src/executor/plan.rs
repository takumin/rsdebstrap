//! The pure kernel of command construction, split out of the impure execution around it.
//!
//! `RealCommandExecutor::execute` resolves binaries through `$PATH` and spawns processes —
//! neither is analysable by a model checker. What *is* analysable is the argv reshaping in the
//! middle of it, and that is the part with a safety obligation attached: under privilege
//! escalation the exec'd program becomes `sudo`/`doas` rather than the requested command, so
//! the command has to be re-inserted as argv[0]. Get that insertion wrong and the caller's
//! arguments silently shift by one — every argument lands on the wrong flag, under
//! root. Nothing else in the program would notice.
//!
//! So it lives here, taking only what it needs and touching nothing: a function a solver can
//! reason about exhaustively. This is the infrastructure-layer half of the verification split
//! described in [`docs/FORMAL_METHODS.md`](../../../docs/FORMAL_METHODS.md) — bounded model
//! checking with Kani, rather than the deductive proofs used for `src/domain/`.

/// Builds the argv handed to the program that is actually exec'd.
///
/// `escalated_argv0` is `Some(command)` when a privilege escalator has displaced the requested
/// command as the exec'd program — the command then has to travel as the escalator's first
/// argument — and `None` when the command is exec'd directly and argv is the caller's own.
///
/// Generic over the element type on purpose: the reshaping is indifferent to what an argument
/// *is*, so the harnesses below can discharge it over a cheap symbolic type instead of over
/// `String`, and the result still applies to the `String` instantiation production uses.
pub(crate) fn plan_argv<T: Clone>(escalated_argv0: Option<T>, args: &[T]) -> Vec<T> {
    match escalated_argv0 {
        Some(argv0) => {
            let mut argv = Vec::with_capacity(args.len() + 1);
            argv.push(argv0);
            argv.extend_from_slice(args);
            argv
        }
        None => args.to_vec(),
    }
}

// Bounded model checking of the argv shape. Compiled only under `cargo kani`, which is why
// `unexpected_cfgs` in Cargo.toml has to know about `cfg(kani)` — a plain `cargo build` never
// sees this module and cannot tell you it has rotted. `task verify:kani` is the thing that can.
//
// `u8` stands in for `String`: `plan_argv` is generic and never inspects an element, so a
// proof over any inhabited type is a proof over all of them, and `u8` keeps the SAT instance
// small enough to discharge in seconds. The length bound is what makes these *bounded* proofs
// — `kani::any()` covers all values but only up to `MAX_ARGS` arguments. Off-by-one bugs do
// not hide past four arguments, so the bound costs nothing real.
#[cfg(kani)]
mod verification {
    use super::plan_argv;

    const MAX_ARGS: usize = 4;

    fn symbolic_args() -> Vec<u8> {
        let len: usize = kani::any();
        kani::assume(len <= MAX_ARGS);
        (0..len).map(|_| kani::any()).collect()
    }

    /// P1 — without escalation the argv is the caller's, unchanged.
    #[kani::proof]
    #[kani::unwind(6)]
    fn unescalated_argv_is_the_input() {
        let args = symbolic_args();
        assert!(plan_argv(None, &args) == args);
    }

    /// P2 — escalation prepends exactly one slot, and it holds the displaced command.
    #[kani::proof]
    #[kani::unwind(6)]
    fn escalation_prepends_exactly_the_command() {
        let args = symbolic_args();
        let argv0: u8 = kani::any();

        let argv = plan_argv(Some(argv0), &args);

        assert!(argv.len() == args.len() + 1);
        assert!(argv[0] == argv0);
    }

    /// P3 — the caller's arguments survive the insertion in order, none dropped, none
    /// duplicated. This is the property whose failure mode is "every flag takes the wrong
    /// value while running as root".
    #[kani::proof]
    #[kani::unwind(6)]
    fn escalation_preserves_the_caller_arguments() {
        let args = symbolic_args();
        let argv0: u8 = kani::any();

        let argv = plan_argv(Some(argv0), &args);

        for i in 0..args.len() {
            assert!(argv[i + 1] == args[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Kani proves these over all inputs; these two pin the concrete `String` instantiation
    // production actually calls, which the generic proof says nothing about on its own.

    #[test]
    fn unescalated_argv_passes_through() {
        let args = vec!["--variant".to_string(), "minbase".to_string()];
        assert_eq!(plan_argv(None, &args), args);
    }

    #[test]
    fn escalated_argv_carries_the_command_first() {
        let args = vec!["--variant".to_string(), "minbase".to_string()];
        assert_eq!(
            plan_argv(Some("/usr/bin/mmdebstrap".to_string()), &args),
            vec![
                "/usr/bin/mmdebstrap".to_string(),
                "--variant".to_string(),
                "minbase".to_string(),
            ]
        );
    }
}
