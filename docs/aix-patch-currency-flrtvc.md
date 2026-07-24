# AIX patch currency and FLRTVC: how to know if you're exposed

If you run IBM Power, you already know the quiet problem: AIX and VIOS are extraordinarily stable, and that stability breeds silence. Systems run for years without a reboot, the person who built them has retired, and nobody is quite sure what is current, what is exposed, or what is actually patched. Patch currency is how you replace assumption with evidence.

This is a practical, vendor-honest guide to understanding your AIX or VIOS patch posture — what to check, why it matters, and what "good" looks like. It uses the real commands, the real tools, and calls out the things that go wrong in practice. At the end we note how [AIXray](https://powertruesystems.com/aixray) — a free, open-source, read-only assessment — collects the same evidence in one pass, so you can choose to do it by hand or let the tool do the gathering.

**Two ground rules for any honest patch review.** First, currency is a snapshot: what is measurably true *right now*. A system that was patched last week is not patched today without another check. Second, when evidence is missing or unreadable, the honest answer is "not assessed" — not a hopeful "looks fine." Keep both rules in mind and your review will be worth trusting.

## 1. Inventory installed filesets — what is actually on the system?

Before you can know what is missing, you need to know what is present. `lslpp -L` lists every fileset and fix installed on the system — not the packages you *think* are there, but the ones thebos recorder actually knows about. Filter to what matters: `lslpp -L | grep -i bos`, `lslpp -L | grep -i perl`, and so on — or run `lslpp -aLc` for a full, machine-parseable inventory of all installed filesets, their states, and checksums.

Look for the filesets that carry CVEs: `bos.rte`, `perl`, `openssl`, `ssh`, `java`, `httpd`. These are the ones IBM patches first when something goes loud. `oslevel -s` prints something like `7200-03-05-241217` (major_minor-TL-SL-datestamp); a system on an old TL while the rest of your estate is current is already a finding.

**Why it matters:** you cannot assess exposure against a fileset that is not inventory'd. The bos recorder is the ground truth — anything else is an assumption.

**What good looks like:** a clear picture of installed filesets, a technology level that matches your standard, and a service pack that is current or on a documented upgrade path.

## 2. Technology level and service pack currency — how current is the base?

`oslevel -s` is the single most important command for patch posture. It tells you the AIX release, the technology level (TL), the service pack (SL), and the date the image was built. Compare that against the latest TL/SL published by IBM — `oslevel -r 7200-0500` (for example) will tell you whether a specific TL is even installed.

The gap between your TL/SL and IBM's latest is not automatically a vulnerability, but it *is* a signal. IBM bundles security fixes into new TLs and SLs, so the further behind you are, the more cumulative fixes you are missing. A system on TL01 when TL05 is current has skipped multiple rounds of security hardening.

**Why it matters:** a lagging technology level is a compounding risk — every missed SL is a missed collection of security fixes, and the gap widens with each release.

**What good looks like:** a supported TL and SL within one or two releases of IBM's current, with a documented plan if you are further behind.

## 3. FLRTVC — the Fix Level Recommendation Tool, what it actually does

IBM's Fix Level Recommendation Tool (FLRTVC) is the closest thing the platform has to a vulnerability scanner for patch gaps. It maps known-vulnerable filesets and missing interim fixes (ifixes) to *your* system's inventory. Unlike vague "hardening" guidance, FLRTVC output is concrete and prioritized: it tells you exactly which filesets are at risk, which ifixes close the gap, and (where applicable) how severe the underlying issue is.

FLRTVC data is not live — it is based on IBM's advisory and fix data, so it reflects the state of IBM's published fixes at the time the reference data was current. A system with zero FLRTVC hits is not guaranteed secure (zero-day is zero-day), but it is guaranteed to have no known-vulnerable filesets from IBM's published list that you have missed.

**Why it matters:** FLRTVC translates "there are CVEs" into "here is exactly what is installed, here is what is missing, and here is what you do about it." That is actionable intelligence, not noise.

**What good looks like:** no outstanding high-severity FLRTVC hits, and any medium/low hits that remain have a documented reason — legacy application dependency, approved risk acceptance, or pending migration.

## 4. Interim fixes (ifixes) — are they cleanly applied, or quietly broken?

An ifix is a patch that targets a specific fileset without requiring a full technology level upgrade. They are essential, they are frequent, and they can fail silently. `emgr -l` lists every effective package (ifix) installed on the system. Look beyond "installed" — check that the ifix is effective, not superseded, and not partially applied. An ifix that was superseded by a later TL is fine; an ifix that is listed but its files are already overwritten by a base level update is a gap.

A partial or superseded ifix is its own failure mode — it creates the appearance of being patched while the vulnerable fileset remains exposed. Overlapping ifixes targeting the same fileset can also mask each other.

**Why it matters:** an ifix that is supposed to be there but is not actually effective is worse than no ifix at all. It gives false confidence.

**What good looks like:** ifixes cleanly applied, current, and not superseded by a base-level update. A clean `emgr -l` with no superseded or partially applied packages.

## 5. Putting it together — what "good" looks like

Good patch posture is not about being on the absolute latest release. It is about being intentional, documented, and current enough to have no outstanding high-severity gaps. Specifically:

- **No outstanding high-severity FLRTVC hits.** Medium and low hits are acceptable with documentation.
- **Ifixes are clean and current.** `emgr -l` shows effective packages, no superseded or partial gaps.
- **Technology level is known and current.** You can name your TL/SL and justify the gap against IBM's latest.
- **There is a review cadence.** New IBM advisories land on a schedule; someone reviews them. The cadence might be weekly, monthly, or per-TL — but it exists, it is known, and it is followed.
- **Missing evidence is reported as NOT_ASSESSED.** If `lslpp` fails, `emgr` returns an error, or `oslevel` is unavailable, the honest answer is "not assessed" — not a hopeful guess.

## 6. Automating the review — AIXray

Working through all of this by hand is tedious, and the biggest risk is inconsistency — you check ifixes carefully on one LPAR and skip them on the next because you are tired. This is exactly the gap [AIXray](https://powertruesystems.com/aixray) was built to close.

AIXray is a free, open-source (Apache-2.0) assessment that collects patch currency evidence — installed filesets (`lslpp`), technology level and service pack (`oslevel`), ifix state (`emgr`), and FLRTVC-reference gap analysis — in one read-only pass. It produces an HTML or JSON report you keep, so you can compare posture across systems or track changes over time.

Because it is open source, you do not have to take any of that on faith — the source, the per-check manifests, and the SHA-256 hashes are all public on [GitHub](https://github.com/PowerTrueSYS/aixray-public), so a cautious admin can read exactly what runs before it runs.

Download it, review it, copy it to your AIX or VIOS host, and run:

```sh
chmod 700 aixray-aix.sh
./aixray-aix.sh
```

You will get `aixray-<hostname>-<date>.html` in the current directory — open it in a browser, or save it as PDF to hand to your team.

## If you'd rather have it fixed and watched

Running the audit tells you where you stand. Acting on it is the next question. AIXray is made by [PowerTrue Systems](https://powertruesystems.com), a managed-services firm run by senior AIX/Power engineers — so if your report surfaces things you'd rather not carry alone, we can help you remediate them and keep the systems monitored over time. That is entirely optional. The tool is free and yours to use forever, whether or not we ever talk. Run the audit, keep the evidence, and decide from there.
