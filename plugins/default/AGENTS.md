# plugins/default/AGENTS.md

Rules for the default plugins. Read `plugins/AGENTS.md` first.

This directory holds one plugin for each required slot. chaperone does not start unless each slot has a plugin. A default fills its slot when `install.json` names no other plugin for that slot. Plugins of more than one kind sit here side by side. This is the only directory where that happens.

## The default set

| Slot | Kind | Plugin | Behavior |
|---|---|---|---|
| front door | adapter | MCP over streamable HTTP | Serves the manifest and tool calls to an app |
| identity | decision | bearer token | Resolves a bearer token to an app instance by its SHA-256 digest. Constant-time compare. Refuses text that is not a 64-character hex token. |
| secret source | adapter | secret files | One file per secret, mode 0600, owner checked |
| audit sink | adapter | JSONL file | Appends one line per call and syncs it before return |
| approval channel | effect | deny all | Answers `Denied("no approval channel")` to every request |

The build steps in `docs/design.md` section 13 add each plugin.

## Rules

1. A default plugin is the most conservative choice for its slot. When in doubt, it denies.
2. A default plugin has no configuration that can weaken a guarantee.
3. A default plugin may never use `"secret_delivery": "env"`.
4. Removing or renaming a default plugin changes `docs/design.md` in the same pull request.
