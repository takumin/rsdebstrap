//! The four-state override model shared by `privilege` and `isolation`.
//!
//! A profile may say four different things about an overridable setting: nothing at all,
//! "use whatever the profile default is", "off", or an explicit value. [`Tri`] is that
//! choice as data and [`resolve`] is the single rule that collapses it against the profile
//! default. `Privilege` and `TaskIsolation` differ only in their wire syntax and in whether
//! a default is always available — the decision itself is this one function, so a bug fixed
//! here is fixed for both.
//!
//! The specification these functions are held to is written out in
//! [`docs/FORMAL_METHODS.md`](../../../docs/FORMAL_METHODS.md) as properties R1–R8 and
//! discharged two ways: exhaustively over the finite state space in
//! `tests/resolution_spec_test.rs` (runs in `cargo test`), and symbolically over an
//! abstract element type by the Verus proofs in `verify/verus/`. Change a match arm below
//! and both fail.

/// A setting that a task may override, before it has been resolved against the defaults.
///
/// `T` is the setting's payload — the escalation method for privilege, the backend config
/// for isolation. Nothing here inspects it, which is precisely why the properties proved
/// about this module hold for any payload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri<T> {
    /// The task said nothing: fall back to the profile default, and accept its absence.
    Inherit,
    /// The task demanded the profile default: its absence is a configuration error.
    UseDefault,
    /// The task opted out.
    Disabled,
    /// The task supplied its own value, which outranks the default.
    Explicit(T),
}

impl<T> Tri<T> {
    /// Whether this state still needs [`resolve`] before it can be acted on.
    ///
    /// `Inherit` and `UseDefault` carry no decision on their own — reading a setting out of
    /// them means reading it out of thin air, so the accessors on the adapter types treat
    /// it as a logic error.
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Disabled | Self::Explicit(_))
    }
}

/// The one way resolution can fail: `UseDefault` with nothing to default to.
///
/// Deliberately payload-free. Turning it into a message belongs to the adapter that knows
/// which YAML key the user actually wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultUnavailable;

/// Collapses an override against the profile default.
///
/// `Ok(Some(v))` means the setting applies with value `v`, `Ok(None)` means it does not
/// apply at all, and the error means the profile asked for a default it never configured.
///
/// # Errors
///
/// Returns [`DefaultUnavailable`] for `UseDefault` when `default` is `None`. This is the
/// only input that fails, and `Inherit` deliberately does *not*: an unspecified setting
/// silently degrades to "off", while an explicitly requested one must not.
pub fn resolve<T>(state: Tri<T>, default: Option<T>) -> Result<Option<T>, DefaultUnavailable> {
    match state {
        Tri::Inherit => Ok(default),
        Tri::UseDefault => match default {
            Some(value) => Ok(Some(value)),
            None => Err(DefaultUnavailable),
        },
        Tri::Disabled => Ok(None),
        Tri::Explicit(value) => Ok(Some(value)),
    }
}

/// [`resolve`] for settings whose default always exists, and which therefore cannot fail.
///
/// Isolation is in this position: `IsolationConfig` has a `Default`, so the profile always
/// has one to hand. Property R8 pins this against [`resolve`] rather than leaving the two
/// implementations to drift, and R7 is what makes `Inherit` and `UseDefault` indistinguishable
/// here — a fact `TaskIsolation` relies on and previously only asserted in a comment.
pub fn resolve_with_default<T>(state: Tri<T>, default: T) -> Option<T> {
    match state {
        Tri::Inherit | Tri::UseDefault => Some(default),
        Tri::Disabled => None,
        Tri::Explicit(value) => Some(value),
    }
}

/// Writes a resolution outcome back into the state space, for the `resolve_in_place` forms.
///
/// The result is always [`Tri::is_resolved`], which is what lets the accessors on the
/// adapter types treat an unresolved state as unreachable rather than as a case to handle.
pub fn collapse<T>(resolved: Option<T>) -> Tri<T> {
    match resolved {
        Some(value) => Tri::Explicit(value),
        None => Tri::Disabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The exhaustive treatment lives in `tests/resolution_spec_test.rs`; these pin the
    // decision table itself, so a reader can see the intended mapping without running a
    // solver.

    #[test]
    fn decision_table() {
        assert_eq!(resolve(Tri::Inherit, Some('d')), Ok(Some('d')));
        assert_eq!(resolve(Tri::Inherit, None::<char>), Ok(None));
        assert_eq!(resolve(Tri::UseDefault, Some('d')), Ok(Some('d')));
        assert_eq!(resolve(Tri::UseDefault, None::<char>), Err(DefaultUnavailable));
        assert_eq!(resolve(Tri::Disabled, Some('d')), Ok(None));
        assert_eq!(resolve(Tri::Explicit('x'), Some('d')), Ok(Some('x')));
    }

    #[test]
    fn only_collapsed_states_are_resolved() {
        assert!(!Tri::<char>::Inherit.is_resolved());
        assert!(!Tri::<char>::UseDefault.is_resolved());
        assert!(Tri::<char>::Disabled.is_resolved());
        assert!(Tri::Explicit('x').is_resolved());
    }
}
