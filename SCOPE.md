# Scope and Safety

This lab exists to practise defensive triage. It is deliberately boring and contained.

## In scope

- The victim VM's private address on the host-only network
- The Wazuh manager, indexer and dashboard on the host, reachable only from localhost
- Authorised attack simulations generated from the host shell against the victim VM
- Synthetic test accounts, test cron jobs and test web-shell files created by me

## Out of scope

- Any host on the internet
- Any network belonging to an employer, a client, or a government agency
- Real malware samples, real command-and-control infrastructure, real credentials
- Scanning or exploiting anything I do not own or administer
- Publishing details of authorised assessment work performed under NDA

## Rules

1. All addresses used are RFC1918 or QEMU user-network addresses.
2. The lab network has no route to any production network.
3. Test accounts use throwaway names and are removed after each scenario.
4. The VM is snapshotted before a scenario and reverted after evidence is captured.
5. Malicious-looking payloads are non-functional test strings or local callbacks only.
6. No employer, agency or client is named anywhere in this repository.

## Data handling

No personal data, no production logs, no real user accounts. Any screenshot that
contains a hostname, username or address from outside this lab is redacted before
commit.
