# operation obsidian mirage: Executive Report Rubric

## Scenario-specific required conclusions

The deception/noise set is designed to punish single-indicator conclusions. Identify the small subset of events that share actor infrastructure, credentials, and time; classify the rest as decoys or ordinary activity. A domain, process string, or isolated alert is insufficient without a corroborating execution or network event. Preserve confidence levels and explicitly list unresolved pivots.

## Scoring

- 30% accurate, normalized timeline with artifact citations
- 25% complete entry, pivot, persistence, privilege, and impact analysis
- 20% correct clustering of related, unrelated, benign, and false-signal activity
- 15% disciplined confidence labels and treatment of telemetry gaps
- 10% executive-quality remediation, ownership, and sequencing

## Automatic deductions

- Unsupported attribution or invented observables
- Collapsing every suspicious event into a single incident
- Treating attempted access as successful access
- Treating access as exfiltration without transfer or receipt evidence
- Treating missing logs as proof that activity did not occur
- Omitting material contradictory or benign evidence

Every high-impact conclusion should cite two independent artifacts where available and preserve exact identities, hosts, IP addresses, object names, and timestamps.
