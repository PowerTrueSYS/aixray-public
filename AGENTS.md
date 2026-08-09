# aixray-public

The **public, open-source** face of AIXray and the site content behind
`powertruesystems.com/aixray`. Everything here is customer- and search-visible. This file
carries the working rules for this repository.

## This repo is public

**Anything committed here is public immediately and permanently.** No client data, no lab
hostnames, no internal pricing, no roadmap, no internal decision references. A hostname, IP, or
serial that looks like a customer estate is a stop-and-escalate.

**The private engine lives in `aixray`.** This repo carries the distributed artifact and the
public documentation, not the build system.

## Repo-specific rules

**The product claims here are load-bearing.** "Runs as a single ksh88 file under AIX `/bin/sh`",
"makes zero network calls during assessment execution", "reports findings without remediating
the host", "changes no system configuration and sends no assessment data away from the host" —
these are commitments a customer relies on and a competitor will test. Never widen a claim to
make copy read better, and never let a claim drift ahead of what the shipped artifact does.

**Closed egress is a product claim, not an inconvenience.** Anything that would make the
assessment reach the network breaks the central promise.

**A version number in the copy must match the shipped artifact.** Documentation that describes
a version we have not published is a false claim on a public page.

**No remediation.** AIXray reads and reports. Any change that mutates a host contradicts the
product.
