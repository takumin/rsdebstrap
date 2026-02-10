//! Bootstrap backend configuration enum.

use serde::Deserialize;

use super::BootstrapBackend;
use super::debootstrap::DebootstrapConfig;
use super::mmdebstrap::MmdebstrapConfig;
use crate::error::RsdebstrapError;
use crate::privilege::{Privilege, PrivilegeDefaults, PrivilegeMethod};

/// Bootstrap backend configuration.
///
/// This enum represents the different bootstrap tools that can be used.
/// The `type` field in YAML determines which variant is used.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Bootstrap {
    /// mmdebstrap backend
    Mmdebstrap(MmdebstrapConfig),
    /// debootstrap backend
    Debootstrap(DebootstrapConfig),
}

impl Bootstrap {
    /// Returns a reference to the underlying backend as a trait object.
    ///
    /// This allows calling `BootstrapBackend` methods without matching
    /// on each variant explicitly.
    pub fn as_backend(&self) -> &dyn BootstrapBackend {
        match self {
            Bootstrap::Mmdebstrap(cfg) => cfg,
            Bootstrap::Debootstrap(cfg) => cfg,
        }
    }

    /// Returns a reference to the privilege setting of the bootstrap backend.
    pub fn privilege(&self) -> &Privilege {
        match self {
            Bootstrap::Mmdebstrap(cfg) => &cfg.privilege,
            Bootstrap::Debootstrap(cfg) => &cfg.privilege,
        }
    }

    /// Resolves the privilege setting against profile defaults, replacing
    /// the stored `Privilege` with a fully resolved variant.
    pub fn resolve_privilege(
        &mut self,
        defaults: Option<&PrivilegeDefaults>,
    ) -> Result<(), RsdebstrapError> {
        match self {
            Bootstrap::Mmdebstrap(cfg) => cfg.privilege.resolve_in_place(defaults),
            Bootstrap::Debootstrap(cfg) => cfg.privilege.resolve_in_place(defaults),
        }
    }

    /// Returns the resolved privilege method for the bootstrap backend.
    ///
    /// Should only be called after `resolve_privilege()`.
    pub fn resolved_privilege_method(&self) -> Option<PrivilegeMethod> {
        self.privilege().resolved_method()
    }
}
