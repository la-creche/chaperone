# crates/editor/AGENTS.md

Rules for the policy editor. Read the root `AGENTS.md` first.

The editor is a separate program. It serves HTML forms that edit `policy.json`. It is separate so that a change to the editor needs no chaperone restart. It has a 1:1 relationship with one chaperone deployment.

## Rules

1. Run as a dedicated OS user. That user can write `policy.json` and open the admin socket. It cannot write `install.json`. It cannot read the secrets directory.
2. Listen on its own port, never on the front-door port. Require the editor's own admin token.
3. Render HTML on the server. Use plain forms. Do not add a JavaScript framework.
4. Build each form from the schema that the admin socket returns. A new plugin needs no editor code.
5. To save:
   1. Send the candidate file to `POST /check`.
   2. If the check fails, show the errors and keep the old file.
   3. If the check passes, keep the previous version.
   4. Write the new file to a temporary path and rename it into place.
6. Show that a token digest exists. Never show a token or a secret value.

## Never do these

1. Do not check a policy with your own code. The installed chaperone is the only authority, through `POST /check`.
2. Do not link `crates/core` to read or check `policy.json`. Use the admin socket, so the editor and chaperone cannot drift.
3. Do not write `install.json`. Do not read a secret.
4. Do not bind `0.0.0.0`.
