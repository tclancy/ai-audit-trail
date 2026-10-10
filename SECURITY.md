# Security policy

## Reporting

Email the address in the repository profile with the subject line `ai-audit-trail security`. Do not open a public issue for anything that could let a record be forged, a chain be rewritten undetected, an approval be replayed, or key material be exposed.

You will get an acknowledgement within 72 hours and a decision (fix, won't fix with reasoning, or need-more-information) within 14 days. Credit is given unless you ask otherwise.

## Scope

In scope: anything that violates an invariant in `SPEC.md` §7, any consumer rule in §6, or any threat-model claim in §10. Out of scope: the compose demo as an isolation boundary (it is documented not to be one), and collusion across the owners named in §10.

## Supported versions

Pre-release: `main` only.

## Wire-format promise

Schema version `v` changes only with a major release. Records written under any released `v` verify forever with a verifier that supports that `v`. A verifier never silently accepts a record under an unsupported `v`.
