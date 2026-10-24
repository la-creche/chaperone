//! The default identity plugin. It hashes the bearer token with SHA-256 and
//! compares the digest with every token digest of every app instance, in
//! constant time. A match resolves to that app instance with its full
//! reach. No bearer, or no match, resolves to nothing (G4).

use chaperone_core::{Caller, Credentials, Identity, Policy, Reach};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The bearer identity plugin.
#[derive(Debug, Default, Clone, Copy)]
pub struct BearerIdentity;

impl Identity for BearerIdentity {
    fn resolve(&self, credentials: &Credentials<'_>, policy: &Policy) -> Option<Caller> {
        let bearer = credentials.bearer?;
        #[expect(
            clippy::disallowed_methods,
            reason = "G9: the token is hashed at once and never stored"
        )]
        let digest = Sha256::digest(bearer.expose().as_bytes());

        // Compare against every digest, so the time does not depend on
        // which app instance matches. The policy holds each digest once.
        let mut found = None;
        for (id, app) in policy.apps() {
            for known in app.digests() {
                let same: bool = known.as_bytes().ct_eq(digest.as_slice()).into();
                if same {
                    found = Some(id);
                }
            }
        }

        found.map(|app| Caller {
            app: app.clone(),
            reach: Reach::Full,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chaperone_core::{
        AppId, Bearer, Catalog, Found, InstallFile, Location, Manifest, PluginKey,
    };

    use super::*;

    fn policy(digests: &[&str]) -> Policy {
        let mut catalog = Catalog::new();
        for (name, kind, slot, hook) in [
            ("mcp-http", "adapter", "front_door", "front_door"),
            ("bearer", "decision", "identity", "identity"),
            ("secret-files", "adapter", "secret_source", "secret_source"),
            ("audit-jsonl", "adapter", "audit_sink", "audit_sink"),
        ] {
            let text = format!(
                r#"{{"name":"{name}","version":"1","kind":"{kind}","slot":"{slot}","hooks":["{hook}"]}}"#
            );
            let manifest = Manifest::read(text.as_bytes()).unwrap();
            catalog.insert(
                PluginKey::from_manifest(&manifest),
                Found {
                    location: Location::Default,
                    manifest,
                },
            );
        }
        let manifest = Manifest::read(
            br#"{"name":"deny-all","version":"1","kind":"effect","slot":"approval_channel",
                "hooks":["approval"],"command":["deny-all"]}"#,
        )
        .unwrap();
        catalog.insert(
            PluginKey::from_manifest(&manifest),
            Found {
                location: Location::Default,
                manifest,
            },
        );

        let install = InstallFile::read(br#"{"version":1}"#).unwrap();
        let setup = chaperone_core::resolve(&install, &catalog).unwrap();
        let list = digests
            .iter()
            .map(|digest| format!("\"{digest}\""))
            .collect::<Vec<_>>()
            .join(",");
        let text = format!(
            r#"{{"version":1,"apps":{{"librechat":{{"token_sha256":[{list}],
                "limits":{{"calls_per_minute":1,"max_pending_gates":0}}}}}}}}"#
        );
        Policy::load(text.as_bytes(), &setup, &[]).unwrap()
    }

    fn sha256_hex(text: &str) -> String {
        Sha256::digest(text.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn resolve(policy: &Policy, token: Option<&str>) -> Option<Caller> {
        let bearer = token.map(|token| Bearer::new(token.to_owned()));
        let headers = BTreeMap::new();
        let credentials = Credentials {
            bearer: bearer.as_ref(),
            headers: &headers,
        };
        BearerIdentity.resolve(&credentials, policy)
    }

    #[test]
    fn a_known_token_resolves_to_its_app() {
        let policy = policy(&[&sha256_hex("tok-one")]);
        let caller = resolve(&policy, Some("tok-one")).unwrap();
        assert_eq!(caller.app, AppId::try_new("librechat").unwrap());
        assert_eq!(caller.reach, Reach::Full);
    }

    #[test]
    fn both_digests_work_during_a_rotation() {
        let policy = policy(&[&sha256_hex("old"), &sha256_hex("new")]);
        assert!(resolve(&policy, Some("old")).is_some());
        assert!(resolve(&policy, Some("new")).is_some());
    }

    #[test]
    fn an_unknown_token_or_no_token_resolves_to_nothing() {
        let policy = policy(&[&sha256_hex("tok-one")]);
        assert!(resolve(&policy, Some("tok-two")).is_none());
        assert!(resolve(&policy, Some("")).is_none());
        assert!(resolve(&policy, None).is_none());
    }
}
