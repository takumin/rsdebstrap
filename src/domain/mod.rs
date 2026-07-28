//! Domain layer: the decision rules the rest of the program obeys.
//!
//! Everything under this module is a **total, pure function over plain data**. No I/O, no
//! `serde`, no `anyhow`, no `tracing`, no borrowed process state — and, by the dependency
//! rule, no `use` of any other module in this crate. The adapter layers depend inward on
//! this one, never the reverse: `src/privilege.rs` and `src/isolation/mod.rs` own the YAML
//! wire shapes and the user-facing error strings, then delegate the actual decision here.
//!
//! The purity is not stylistic. It is what makes the rules mechanically verifiable: the
//! functions here are the only ones in the crate whose behaviour is fully determined by
//! their arguments, so a solver can reason about them without modelling the filesystem or
//! the process table. See [`docs/FORMAL_METHODS.md`](../../docs/FORMAL_METHODS.md) for
//! which tool verifies which layer and why.

pub mod resolution;
