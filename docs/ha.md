# Home Assistant

This document states how chaperone reaches Home Assistant and what an agent may read there. `docs/design.md` section 12 holds the plugin rules. This document holds the operator's setup.

## 1. The three parts

| Part | What it does | Where it is |
|---|---|---|
| `ha-call` | An agent calls a Home Assistant service. A fence checks each `entity_id` against the entity list of the app instance. | `plugins/decision/included/ha-call` and `plugins/effect/included/ha-call` |
| `ha-approval` | chaperone holds a gated call. The plugin asks the operator's approval flow to push a card to a phone. The tap comes back to the plugin. | `plugins/effect/included/ha-approval` |
| The read user | An agent reads entity states through a separate Home Assistant user with a read allowlist. | `ha/agent-read-policy.json` |

chaperone does not read entity states itself. The read user is an operator setup in Home Assistant.

## 2. The approval flow

The approval flow is outside this repository. It is a Node-RED instance in front of Home Assistant. It sends the push to the phone and receives the tap. Section 12 of `docs/design.md` gives the two legs and the payloads.

Keep the flow in a repository that no agent can read or write. If an agent can change the flow, the agent can approve its own call.

These rules bind from the chaperone side:

1. The gate ID and the job ID never contain an underscore. The flow joins and splits its action strings on an underscore.
2. The flow accepts a tap only from the account of the operator. The check is on the account, not on the phone. A failed check ends in a denial.
3. The flow reaches Home Assistant by a fixed address. Name resolution by mDNS is unreliable for a daemon.
4. Two hops cross the network in plain text: the flow to Home Assistant, and the tap to `ha-approval`. The hop from `ha-approval` to the flow stays on a loopback address. Put a host firewall rule on the tap hop.

## 3. The read allowlist

`ha/agent-read-policy.json` is the `policy` of a custom Home Assistant user group. Only the read user holds this group.

The file lists domains. Each domain has `{"read": true}`. A domain that the file does not list is invisible to the read user. A new integration is hidden until the operator adds its domain.

JSON has no comments, so the reasons are here.

### 3.1 Readable domains

The file lists 20 domains: `sensor`, `binary_sensor`, `switch`, `light`, `number`, `select`, `update`, `media_player`, `cover`, `input_boolean`, `input_number`, `fan`, `remote`, `counter`, `climate`, `weather`, `time`, `sun`, `vacuum` and `event`.

The `sun` domain is required. The entity `sun.sun` is the visible control of the policy. The operator's own tool that writes the policy into Home Assistant lives outside this repository. That tool should refuse a file without this domain.

### 3.2 Hidden domains

| Domains | Why |
|---|---|
| `camera`, `person`, `device_tracker` | They show where people are. The policy never lists them. The operator's tool that writes the policy should refuse a file that lists one. |
| `zone`, `image`, `group`, `alarm_control_panel` | They show presence. The state of the home zone is the count of people at home. An armed-away state says that nobody is home. |
| `automation`, `script`, `scene` | Each visible entity costs an admin-only configuration fetch for each search with a query. That fetch fails with HTTP 401 and counts as a failed login. The `last_triggered` field of an arrival automation also shows presence. |
| `button`, `text`, `notify`, `conversation`, `ai_task`, `stt`, `tts`, `wake_word`, `assist_satellite` | They have no read value. |

Only the first row is fixed. The operator may edit the other rows. After an edit, write the policy into Home Assistant again with the same tool.

### 3.3 What a domain allowlist cannot do

A domain allowlist cannot subtract entities from a domain. Phone sensors live in `sensor` and `binary_sensor`, and they show where a person is. Turn them off at the source. In the Home Assistant companion app, open Settings, then Sensors, and disable the location, network name, activity and last-update sensors. Or disable the entity in Home Assistant.

### 3.4 The login attempt threshold

Do not set `login_attempts_threshold` in the `http:` block of Home Assistant while agents read through the read user. Home Assistant books each REST 401 for that user as a failed login from the address of the agent host. With a threshold, one read of a list that holds hidden IDs bans that host. The ban also stops `ha-call` and the websocket of the approval flow.
