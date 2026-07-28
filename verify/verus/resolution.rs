// Deductive proofs of the resolution specification (docs/FORMAL_METHODS.md, R1-R8) for
// `src/domain/resolution.rs`.
//
// Verified with:
//
//     verus --crate-type=lib verify/verus/resolution.rs
//
// (or `task verify:verus`, which is what CI runs). This is a standalone Verus source file, not
// a Cargo crate: `vstd` and `builtin` come from the Verus installation, and the file is
// deliberately outside the `rsdebstrap` crate graph so no part of the shipped build depends on
// a toolchain that most contributors will not have installed.
//
// What this buys over `tests/resolution_spec_test.rs`, which checks the same properties: that
// file enumerates a two-element payload type and is therefore a proof only for payloads of
// that shape. The proofs here are universally quantified over `T` and hold for every payload
// the model could ever carry - including the isolation backends that do not exist yet. See
// docs/FORMAL_METHODS.md#why-both.
//
// Correspondence with the Rust source. `Outcome<T>` here stands for the Rust
// `Result<Option<T>, DefaultUnavailable>`:
//
//     Outcome::Applies(v)   ==  Ok(Some(v))
//     Outcome::Inapplicable ==  Ok(None)
//     Outcome::Unavailable  ==  Err(DefaultUnavailable)
//
// It is a flat enum rather than nested generics because Verus reasons about datatypes far more
// predictably than about layered `Result<Option<_>, _>`, and the isomorphism is total either
// way. Every other name matches its Rust counterpart one for one; that correspondence is
// maintained by hand, and `tests/resolution_spec_test.rs` is what would catch it going stale
// on the Rust side.

use vstd::prelude::*;

verus! {

// -------------------------------------------------------------------------------------------
// The model
// -------------------------------------------------------------------------------------------

/// Mirrors `domain::resolution::Tri`.
pub enum Tri<T> {
    Inherit,
    UseDefault,
    Disabled,
    Explicit(T),
}

/// Mirrors `Result<Option<T>, DefaultUnavailable>`; see the correspondence above.
pub enum Outcome<T> {
    Applies(T),
    Inapplicable,
    Unavailable,
}

/// Discriminator helpers. Written as `match` rather than with the `is` operator so the
/// proofs below depend on nothing but datatype pattern matching.
pub open spec fn is_inherit<T>(state: Tri<T>) -> bool {
    match state {
        Tri::Inherit => true,
        _ => false,
    }
}

pub open spec fn is_use_default<T>(state: Tri<T>) -> bool {
    match state {
        Tri::UseDefault => true,
        _ => false,
    }
}

/// A state that already carries its own answer, so the defaults cannot influence it.
pub open spec fn is_decided<T>(state: Tri<T>) -> bool {
    match state {
        Tri::Disabled => true,
        Tri::Explicit(_) => true,
        _ => false,
    }
}

/// Mirrors `Tri::is_resolved`.
pub open spec fn is_resolved<T>(state: Tri<T>) -> bool {
    is_decided(state)
}

pub open spec fn is_unavailable<T>(outcome: Outcome<T>) -> bool {
    match outcome {
        Outcome::Unavailable => true,
        _ => false,
    }
}

pub open spec fn has_default<T>(default: Option<T>) -> bool {
    match default {
        Option::Some(_) => true,
        Option::None => false,
    }
}

/// Mirrors `domain::resolution::resolve`.
pub open spec fn resolve<T>(state: Tri<T>, default: Option<T>) -> Outcome<T> {
    match state {
        Tri::Inherit => match default {
            Option::Some(value) => Outcome::Applies(value),
            Option::None => Outcome::Inapplicable,
        },
        Tri::UseDefault => match default {
            Option::Some(value) => Outcome::Applies(value),
            Option::None => Outcome::Unavailable,
        },
        Tri::Disabled => Outcome::Inapplicable,
        Tri::Explicit(value) => Outcome::Applies(value),
    }
}

/// Mirrors `domain::resolution::resolve_with_default`.
pub open spec fn resolve_with_default<T>(state: Tri<T>, default: T) -> Option<T> {
    match state {
        Tri::Inherit => Option::Some(default),
        Tri::UseDefault => Option::Some(default),
        Tri::Disabled => Option::None,
        Tri::Explicit(value) => Option::Some(value),
    }
}

/// Mirrors `domain::resolution::collapse`.
pub open spec fn collapse<T>(resolved: Option<T>) -> Tri<T> {
    match resolved {
        Option::Some(value) => Tri::Explicit(value),
        Option::None => Tri::Disabled,
    }
}

/// Lifts a successful resolution into an `Outcome`, so R6 and R8 can compare the two
/// representations without an ambient coercion.
pub open spec fn outcome_of<T>(resolved: Option<T>) -> Outcome<T> {
    match resolved {
        Option::Some(value) => Outcome::Applies(value),
        Option::None => Outcome::Inapplicable,
    }
}

// -------------------------------------------------------------------------------------------
// The proofs
// -------------------------------------------------------------------------------------------
//
// R1 (totality and determinism) has no lemma: `resolve` is a Verus `spec fn`, which *is* a
// total mathematical function, so both hold by construction rather than by argument. The
// Rust-side test still checks R1 because a Rust `fn` carries no such guarantee - it can
// diverge or panic, and the enumeration is what rules that out.
//
// Each proof body is an explicit case split. Verus can often find these on its own, but
// spelling them out keeps the obligations stable as the model grows: a new `Tri` variant
// becomes a non-exhaustive-match compile error here rather than a silently weaker proof.

/// R2 - failure is exactly `UseDefault` with no default configured.
pub proof fn r2_failure_iff_use_default_without_default<T>(state: Tri<T>, default: Option<T>)
    ensures
        is_unavailable(resolve(state, default)) <==> (is_use_default(state) && !has_default(
            default,
        )),
{
    match state {
        Tri::Inherit => {},
        Tri::UseDefault => {
            match default {
                Option::Some(_) => {},
                Option::None => {},
            }
        },
        Tri::Disabled => {},
        Tri::Explicit(_) => {},
    }
}

/// R3 - provenance: a resolved value was either written on the task or inherited from the
/// profile default. Nothing else can produce one.
///
/// At the privilege instantiation this is the statement that a task cannot end up escalated
/// unless the profile named an escalation method somewhere.
pub proof fn r3_resolved_values_come_from_state_or_default<T>(
    state: Tri<T>,
    default: Option<T>,
    value: T,
)
    requires
        resolve(state, default) == Outcome::Applies(value),
    ensures
        state == Tri::<T>::Explicit(value) || (default == Option::Some(value) && (is_inherit(state)
            || is_use_default(state))),
{
    match state {
        Tri::Inherit => {},
        Tri::UseDefault => {},
        Tri::Disabled => {},
        Tri::Explicit(_) => {},
    }
}

/// R4 - a decided state is insensitive to the defaults.
pub proof fn r4_decided_states_ignore_defaults<T>(
    state: Tri<T>,
    left: Option<T>,
    right: Option<T>,
)
    requires
        is_decided(state),
    ensures
        resolve(state, left) == resolve(state, right),
{
    match state {
        Tri::Inherit => {},
        Tri::UseDefault => {},
        Tri::Disabled => {},
        Tri::Explicit(_) => {},
    }
}

/// R5 - collapsing a resolution always lands in the resolved half of the state space, which is
/// what lets the accessors treat `Inherit`/`UseDefault` as unreachable after resolution.
pub proof fn r5_collapse_always_produces_a_resolved_state<T>(resolved: Option<T>)
    ensures
        is_resolved(collapse(resolved)),
{
    match resolved {
        Option::Some(_) => {},
        Option::None => {},
    }
}

/// R6 - resolution is idempotent, and stays idempotent under a *different* default. The
/// second half is what makes re-resolution over a shared profile tree safe.
pub proof fn r6_resolution_is_idempotent<T>(resolved: Option<T>, default: Option<T>)
    ensures
        resolve(collapse(resolved), default) == outcome_of(resolved),
{
    match resolved {
        Option::Some(_) => {},
        Option::None => {},
    }
}

/// R7 - with a default configured, `Inherit` and `UseDefault` are the same state.
///
/// This is why `TaskIsolation` may keep both variants for symmetry with `Privilege` without
/// them meaning anything different: its default always exists.
pub proof fn r7_inherit_equals_use_default_when_a_default_exists<T>(default: Option<T>)
    requires
        has_default(default),
    ensures
        resolve(Tri::<T>::Inherit, default) == resolve(Tri::<T>::UseDefault, default),
{
    match default {
        Option::Some(_) => {},
        Option::None => {},
    }
}

/// R8 - the infallible form is a refinement of the fallible one, not a second rule.
pub proof fn r8_resolve_with_default_refines_resolve<T>(state: Tri<T>, default: T)
    ensures
        resolve(state, Option::Some(default)) == outcome_of(
            resolve_with_default(state, default),
        ),
{
    match state {
        Tri::Inherit => {},
        Tri::UseDefault => {},
        Tri::Disabled => {},
        Tri::Explicit(_) => {},
    }
}

} // verus!
