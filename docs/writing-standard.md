# Writing standard: ASD-STE100

Every Markdown document in this repository is written in ASD-STE100 Simplified Technical English (STE). `AGENTS.md` makes this binding for every contributor and every agent.

## 1. Scope

The rule applies to every `.md` file in this tree.

The rule does not apply to:

- Code comments and doc comments. Apply the rules to a new comment when the result stays correct.
- Test fixtures.
- Quoted text. An error message, a command or a log line is quoted as it is.

## 2. What the standard is

ASD-STE100 is a controlled language. The AeroSpace and Defence Industries Association of Europe (ASD) maintains it. The current issue is Issue 9. The standard has two parts:

1. Writing rules. They limit sentence length, grammar and structure.
2. A dictionary of approved words. Each approved word has one meaning.

This repository applies the writing rules in full. It does not reproduce the dictionary, because the dictionary is not licensed for redistribution. This repository does not claim certified compliance with the standard. Get the official text from the ASD download page: <https://www.asd-ste100.org/STE_downloads.html>.

## 3. The writing rules

| Rule | Do | Do not |
|---|---|---|
| Active voice | "chaperone writes the audit line." | "The audit line is written." |
| One instruction per sentence | "Open the file. Read line 3." | "Open the file and read line 3, then check it." |
| Sentence length | 20 words or less in an instruction. 25 words or less in a description. | Compound sentences with stacked clauses. |
| Simple tenses | Present, past, future, imperative. | Present perfect and progressive forms, unless the simple form loses meaning. |
| Articles | Keep "a", "an" and "the". | "Files not backed up are lost." |
| Noun clusters | Three words or less: "policy file path". | "app instance gate wait window value". |
| Paragraphs | One topic. Six sentences or less. | A paragraph that covers two topics. |
| Sequences | A numbered list for three or more steps. | A sequence inside one sentence. |
| Punctuation | A period ends a sentence. | A semicolon. An em dash. |
| Modality | Keep "may" and "can" where the fact is uncertain. | Promote a hedge to a fact. |
| Warnings | State the condition first, then the instruction. | A warning buried in a paragraph. |

## 4. Word rules

1. One word has one meaning. One meaning has one word. Do not rotate synonyms.
2. Use the plainest common word. Write "use", not "utilize". Write "start", not "spin up".
3. Use a verb, not a noun that hides the verb. Write "validate the file", not "perform validation of the file".
4. Do not use idioms, slang or figurative language.
5. Do not use marketing adjectives. Replace the adjective with the measurement that supports the claim, or delete it.
6. Define a technical name once, at first use. Then use the same name every time.

## 5. The project dictionary

Use each name as it is written here. Do not use a synonym for one.

| Name | Meaning |
|---|---|
| app | An agent app that sends tool calls to chaperone, such as the agent runtime in the sandbox. |
| app instance | One deployment of one app. The unit of a grant. |
| grant | What an app instance may reach. The policy file holds it. |
| tool | A named action that an app can call. An upstream provides it. |
| upstream | An effect plugin whose tools an app can see, if granted. |
| plugin | A unit that serves one or more hooks. Its kind is decision, adapter or effect. |
| hook | A named point where chaperone calls a plugin. |
| slot | A hook that exactly one plugin must serve. |
| fence | A rule that can deny or gate a call by its arguments. |
| gate | A hold on one call until a human answers. A gate is pending, then approved, denied or expired. |
| decision | The result of the decision function: allow, deny or gate. |
| front door | The adapter that receives an app's connection. |
| policy file | `policy.toml`. |
| install file | `install.toml`. |
| audit line | One record of one call, written before the result returns. |
| secret | A credential that chaperone holds for a plugin. |
| the operator | The person who runs a deployment. |
| the host | The machine that runs a deployment. |
| a maintainer | A person who can merge to `main`. |

Approved verbs: read, write, start, stop, restart, refuse, allow, deny, gate, approve, validate, load, reload, enable, install, remove, rotate, publish, bind, build.

## 6. Sanitization

A document in this repository names no deployment. Do not write:

- A host name, a LAN address or a domain of a deployment.
- A person, an OS account name or a home directory of a deployment.
- A phone target or a time zone of a deployment.

Write "the operator", "the host" and "the host's LAN address". In an example that needs an address, use `192.0.2.10` and the other TEST-NET-1 addresses.

## 7. Checklist before you commit a document

1. Read the first line. It states what the document is for.
2. Read every sentence once. Delete the first sentence if it announces what follows. Delete the last sentence if it repeats what came before.
3. Find every semicolon and every em dash. Split the sentence.
4. Find every sentence over 20 words in an instruction. Split it.
5. Find every "and then". Make a numbered list.
6. Find every word with two meanings in context. Replace it.
7. Check section 6. The document names no deployment.

## 8. Enforcement

No tool checks this rule. The reviewer checks it. A pull request that adds prose which breaks a rule in this document is not merged until the prose is fixed.
