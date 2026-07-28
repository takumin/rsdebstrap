//! Exhaustive discharge of the resolution specification (`docs/FORMAL_METHODS.md`, R1–R8).
//!
//! The state space of `Tri<T>` is `3 + |T|`, and resolution never inspects `T` beyond moving
//! it — so two distinguishable payloads exhaust every behaviour the model can exhibit, and a
//! loop over 5 states × 3 default configurations is a *complete* case analysis rather than a
//! sample. That is what makes this a proof and not a test suite: there is no untried input.
//!
//! The same properties are stated symbolically over an abstract `T` in `verify/verus/`, where
//! they hold for every payload type rather than for a two-element witness. This file is the
//! part that runs in `cargo test` on every commit; the Verus crate is the part that does not
//! depend on `T` being finite. Keeping both is deliberate — see
//! [`docs/FORMAL_METHODS.md`](../docs/FORMAL_METHODS.md#why-both).
//!
//! The `A*` properties at the bottom close the gap between the verified model and the code
//! that actually ships: they pin `Privilege` and `TaskIsolation` to the domain functions over
//! their own full state spaces, so a proof about `Tri` is a proof about production behaviour.

use rsdebstrap::config::IsolationConfig;
use rsdebstrap::domain::resolution::{self, DefaultUnavailable, Tri};
use rsdebstrap::isolation::TaskIsolation;
use rsdebstrap::privilege::{Privilege, PrivilegeDefaults, PrivilegeMethod};

/// The abstract payload. Two variants, because the model can only ever distinguish "the
/// default's value" from "some other value" — a third would add combinations, not coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Elem {
    A,
    B,
}

/// Every inhabitant of `Tri<Elem>`.
fn all_states() -> Vec<Tri<Elem>> {
    vec![
        Tri::Inherit,
        Tri::UseDefault,
        Tri::Disabled,
        Tri::Explicit(Elem::A),
        Tri::Explicit(Elem::B),
    ]
}

/// Every inhabitant of `Option<Elem>` — the profile either configured a default or did not.
fn all_defaults() -> Vec<Option<Elem>> {
    vec![None, Some(Elem::A), Some(Elem::B)]
}

/// R1 — resolution is total and deterministic: no input panics, and repeating a call cannot
/// change the answer. Totality is what lets every other property be stated without a
/// "provided it returns" caveat.
#[test]
fn r1_total_and_deterministic() {
    for state in all_states() {
        for default in all_defaults() {
            let first = resolution::resolve(state, default);
            let second = resolution::resolve(state, default);
            assert_eq!(first, second, "resolve is not a function at ({state:?}, {default:?})");
        }
    }
}

/// R2 — failure is characterised exactly: `UseDefault` against an unconfigured default, and
/// nothing else. The "only if" direction is the interesting one: it forbids adding a new error
/// case — or widening this one to `Inherit` — without the specification changing first.
#[test]
fn r2_failure_iff_use_default_without_default() {
    for state in all_states() {
        for default in all_defaults() {
            let failed = resolution::resolve(state, default) == Err(DefaultUnavailable);
            let expected = matches!(state, Tri::UseDefault) && default.is_none();
            assert_eq!(failed, expected, "failure condition diverges at ({state:?}, {default:?})");
        }
    }
}

/// R3 — provenance. A resolved value is *always* traceable to something the profile wrote:
/// either the task's own explicit setting, or the profile default it asked to inherit.
///
/// This is the security-relevant one. Read on the privilege instantiation it says that a task
/// can only ever end up running under `sudo`/`doas` because the profile named that method —
/// resolution has no path that conjures escalation out of a state that did not request it.
#[test]
fn r3_resolved_values_come_from_state_or_default() {
    for state in all_states() {
        for default in all_defaults() {
            let Ok(Some(value)) = resolution::resolve(state, default) else {
                continue;
            };
            let from_state = state == Tri::Explicit(value);
            let from_default =
                default == Some(value) && matches!(state, Tri::Inherit | Tri::UseDefault);
            assert!(
                from_state || from_default,
                "{value:?} resolved out of ({state:?}, {default:?}) with no provenance"
            );
        }
    }
}

/// R4 — a task that states its own answer is unaffected by the profile defaults. Changing
/// `defaults` must not be able to alter a `Disabled` or `Explicit` task, which is what makes
/// per-task overrides trustworthy.
#[test]
fn r4_decided_states_ignore_defaults() {
    let decided = [
        Tri::Disabled,
        Tri::Explicit(Elem::A),
        Tri::Explicit(Elem::B),
    ];
    for state in decided {
        for left in all_defaults() {
            for right in all_defaults() {
                assert_eq!(
                    resolution::resolve(state, left),
                    resolution::resolve(state, right),
                    "{state:?} is sensitive to defaults ({left:?} vs {right:?})"
                );
            }
        }
    }
}

/// R5 — resolution is closed: whatever it produces, feeding it back through `collapse` yields
/// a state that is `is_resolved()`. The accessors (`resolved_method`, `resolved_config`) treat
/// the unresolved states as a logic error rather than a case to handle, and this is why.
#[test]
fn r5_collapse_always_produces_a_resolved_state() {
    for state in all_states() {
        for default in all_defaults() {
            let Ok(resolved) = resolution::resolve(state, default) else {
                continue;
            };
            assert!(
                resolution::collapse(resolved).is_resolved(),
                "collapse left ({state:?}, {default:?}) unresolved"
            );
        }
    }
}

/// R6 — resolving twice is resolving once. `resolve_in_place` runs over profile trees where
/// a node can be visited more than once, so a second pass must be a no-op; combined with R4,
/// it must also be a no-op *under a different default*.
#[test]
fn r6_resolution_is_idempotent() {
    for state in all_states() {
        for default in all_defaults() {
            let Ok(once) = resolution::resolve(state, default) else {
                continue;
            };
            for again in all_defaults() {
                assert_eq!(
                    resolution::resolve(resolution::collapse(once), again),
                    Ok(once),
                    "re-resolving ({state:?}, {default:?}) under {again:?} changed the outcome"
                );
            }
        }
    }
}

/// R7 — with a default configured, `Inherit` and `UseDefault` are indistinguishable.
///
/// `docs/ARCHITECTURE.md` flags this as the non-obvious reason `TaskIsolation` keeps both
/// variants despite `IsolationConfig` always having a default. It is a consequence of the
/// model, not a coincidence of that type, and it is now checked rather than asserted in prose.
#[test]
fn r7_inherit_equals_use_default_when_a_default_exists() {
    for default in all_defaults() {
        if default.is_none() {
            continue;
        }
        assert_eq!(
            resolution::resolve(Tri::Inherit, default),
            resolution::resolve(Tri::UseDefault, default),
            "Inherit and UseDefault diverge under {default:?}"
        );
    }
}

/// R8 — the infallible form refines the fallible one. `resolve_with_default` exists so
/// isolation does not have to unwrap an error that cannot happen; this pins it as the same
/// rule rather than a second implementation that could drift from it.
#[test]
fn r8_resolve_with_default_refines_resolve() {
    for state in all_states() {
        for default in [Elem::A, Elem::B] {
            assert_eq!(
                resolution::resolve(state, Some(default)),
                Ok(resolution::resolve_with_default(state, default)),
                "the two forms disagree at ({state:?}, {default:?})"
            );
        }
    }
}

// =============================================================================================
// Adapter agreement — the model is only worth proving if production runs it.
// =============================================================================================

/// Every inhabitant of `Privilege`, paired with the `Tri` it is supposed to project onto.
fn all_privileges() -> Vec<(Privilege, Tri<PrivilegeMethod>)> {
    vec![
        (Privilege::Inherit, Tri::Inherit),
        (Privilege::UseDefault, Tri::UseDefault),
        (Privilege::Disabled, Tri::Disabled),
        (Privilege::Method(PrivilegeMethod::Sudo), Tri::Explicit(PrivilegeMethod::Sudo)),
        (Privilege::Method(PrivilegeMethod::Doas), Tri::Explicit(PrivilegeMethod::Doas)),
    ]
}

/// Every inhabitant of `Option<PrivilegeDefaults>`.
fn all_privilege_defaults() -> Vec<Option<PrivilegeDefaults>> {
    vec![
        None,
        Some(PrivilegeDefaults {
            method: PrivilegeMethod::Sudo,
        }),
        Some(PrivilegeDefaults {
            method: PrivilegeMethod::Doas,
        }),
    ]
}

/// A1 — `Privilege::resolve` *is* the domain rule, over its entire state space. Success values
/// must match; failure must coincide, with the adapter adding only the message.
#[test]
fn a1_privilege_resolve_agrees_with_the_domain() {
    for (privilege, tri) in all_privileges() {
        for defaults in all_privilege_defaults() {
            let expected = resolution::resolve(tri, defaults.as_ref().map(|d| d.method));
            match (privilege.resolve(defaults.as_ref()), expected) {
                (Ok(actual), Ok(want)) => assert_eq!(actual, want, "{privilege:?} / {defaults:?}"),
                (Err(err), Err(DefaultUnavailable)) => {
                    // The domain error is payload-free on purpose; the adapter's job is to
                    // name the key the user has to go fix, so that much is asserted here.
                    assert!(
                        err.to_string().contains("defaults.privilege.method"),
                        "adapter error does not name the offending key: {err}"
                    );
                }
                (actual, want) => {
                    panic!("{privilege:?} / {defaults:?}: got {actual:?}, domain says {want:?}")
                }
            }
        }
    }
}

/// A2 — `resolve_in_place` lands exactly on `collapse` of what `resolve` returned, and the
/// resulting state is always readable by `resolved_method()` without tripping its fallback.
#[test]
fn a2_privilege_resolve_in_place_collapses_the_resolution() {
    for (privilege, _) in all_privileges() {
        for defaults in all_privilege_defaults() {
            let Ok(resolved) = privilege.resolve(defaults.as_ref()) else {
                continue;
            };

            let mut in_place = privilege.clone();
            in_place
                .resolve_in_place(defaults.as_ref())
                .expect("resolve succeeded, so resolve_in_place must too");

            let expected = match resolution::collapse(resolved) {
                Tri::Explicit(method) => Privilege::Method(method),
                _ => Privilege::Disabled,
            };
            assert_eq!(in_place, expected, "{privilege:?} / {defaults:?}");
            assert_eq!(
                in_place.resolved_method(),
                resolved,
                "the post-state does not read back as what was resolved"
            );
        }
    }
}

/// Every inhabitant of `TaskIsolation`. `IsolationConfig` currently has a single value, so the
/// payload axis is a singleton — adding a second backend widens this list, and the R-properties
/// already cover what that does to the model.
fn all_task_isolations() -> Vec<(TaskIsolation, Tri<IsolationConfig>)> {
    vec![
        (TaskIsolation::Inherit, Tri::Inherit),
        (TaskIsolation::UseDefault, Tri::UseDefault),
        (TaskIsolation::Disabled, Tri::Disabled),
        (
            TaskIsolation::Config(IsolationConfig::chroot()),
            Tri::Explicit(IsolationConfig::chroot()),
        ),
    ]
}

/// A3 — `TaskIsolation::resolve` is the infallible domain rule. Its default is always present,
/// so R7 applies and `Inherit`/`UseDefault` must be observationally identical here.
#[test]
fn a3_task_isolation_resolve_agrees_with_the_domain() {
    let defaults = IsolationConfig::chroot();
    for (isolation, tri) in all_task_isolations() {
        assert_eq!(
            isolation.resolve(&defaults),
            resolution::resolve_with_default(tri, defaults.clone()),
            "{isolation:?}"
        );
    }
    assert_eq!(
        TaskIsolation::Inherit.resolve(&defaults),
        TaskIsolation::UseDefault.resolve(&defaults),
        "R7 does not hold for TaskIsolation, whose default is always configured"
    );
}

/// A4 — the isolation counterpart of A2.
#[test]
fn a4_task_isolation_resolve_in_place_collapses_the_resolution() {
    let defaults = IsolationConfig::chroot();
    for (isolation, _) in all_task_isolations() {
        let resolved = isolation.resolve(&defaults);

        let mut in_place = isolation.clone();
        in_place.resolve_in_place(&defaults);

        let expected = match resolution::collapse(resolved.clone()) {
            Tri::Explicit(config) => TaskIsolation::Config(config),
            _ => TaskIsolation::Disabled,
        };
        assert_eq!(in_place, expected, "{isolation:?}");
        assert_eq!(
            in_place.resolved_config(),
            resolved.as_ref(),
            "the post-state does not read back as what was resolved"
        );
    }
}
