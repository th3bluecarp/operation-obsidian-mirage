# Operation Obsidian Mirage — Golden Answer Key

The primary campaign must be reconstructed from the small set of events sharing identities, infrastructure, and sequencing across Entra/M365, endpoint, jump-host, AWS/Kubernetes, and network evidence. The phishing-session PCAP is a valid capture of the credential/session path; Windows Sysmon then establishes execution and the route to `JUMPHOST-01`. The jump-host history and the valid TLS-exfil PCAP/netflow pair establish outbound staging and transfer.

The ransomware SMB burst and recovery notes are a real impact track, but the report must state whether it is operational cover, a second actor, or merely temporally adjacent based on the supplied pivots. The decoy VPN PCAP is deliberately plausible; without matching endpoint or identity activity it is not initial access. Confluence, VPN, and routine cloud actions are likewise contextual until correlated.

The four PCAPs are now structurally valid and represent distinct hypotheses: phishing/session capture, jump-host exfiltration, ransomware SMB activity, and decoy VPN access. Analysts must not merge them solely because they occur in the same window. Cloud and Kubernetes access must be scoped to the exact assumed role/service account and named resources.

Containment priorities are the proven identity/session, affected Windows host, jump-host access and keys, cloud roles/service accounts, ransomware isolation, and the confirmed exfil destination. Preserve the decoy path and unresolved attribution as explicit non-findings.
