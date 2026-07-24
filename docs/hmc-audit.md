# Auditing the HMC alongside your AIX estate — a manual checklist

If you manage Power systems through a Hardware Management Console, you already know the quiet dependency: the HMC is a single point of control for an entire estate. One appliance, one web interface, one set of certificates — and dozens of managed systems that cannot be powered on or recovered without it. An audit of the HMC is not separate from auditing your AIX estate; it is the foundation that makes everything else possible.

This is a practical, vendor-honest manual checklist for auditing an HMC end to end — what to check, why it matters, and what "good" looks like.

**A note on scope.** AIXray v0.1.0 assesses the AIX and VIOS partitions — the workloads behind the HMC. It does not assess the HMC appliance itself. The HMC audit is a complementary, manual pass. Be clear-eyed about scope.

**Two ground rules.** First, an audit reports what is *measurably true right now*; it does not guarantee security, compliance, or recoverability. Second, when evidence is missing, the honest answer is "not assessed" — not a hopeful "looks fine."

## 1. Firmware currency — is the HMC still supported?

Check the HMC firmware level (`lshmc -V` or the web UI **About** page) against IBM's support matrix. Are interim fixes current?

**Why it matters:** unsupported HMC firmware means no security fixes from IBM and no ability to manage newer partition firmware. The HMC does not age gracefully — it is a hard blocker for everything below it.

**What good looks like:** a supported release with current interim fixes, compatible with the partitions it manages. NOT_ASSESSED if the HMC is past end-of-service and you have no IBM support contract.

## 2. User accounts and roles — who can do what?

Review every HMC user account and its role profile (Administrator, Operator, System Administrator). Verify that no one holds Administrator privileges unless they need full control, and that departed personnel accounts are disabled or removed. Shared accounts with broad roles are a violation of least privilege.

**Why it matters:** the HMC controls the power state of every managed system. A compromised credential with Administrator role cascades to the entire estate.

**What good looks like:** individual accounts, roles at the minimum level needed, no active account belonging to someone without HMC access. NOT_ASSESSED if accounts are managed by external LDAP and you have not reviewed it.

## 3. Certificate validity — will trust still hold?

Check the HMC's SSL/TLS certificates (`lscert` or the web UI **Security** section). Look for expired or near-expiry certificates (within 30 days) and verify key length — RSA 2048 minimum, 4096 preferred.

**Why it matters:** certificate expiry can break the trust relationship between the HMC and every managed system. A failed trust chain means partitions cannot be managed through the web console.

**What good looks like:** valid certificates with 90+ days of remaining life, issued by a trusted CA. NOT_ASSESSED if certificate details are not accessible.

## 4. Connectivity to managed systems — does the HMC actually reach everything?

Review the managed-system inventory (`lssyscfg -r lpar -m *`), verify the HMC can reach each system, and check partition states. Look for orphaned entries where a system has been retired but still appears in the list.

**Why it matters:** an HMC that cannot reach a partition cannot help in a failure. Orphaned managed-system entries cause confusion during incident response.

**What good looks like:** every managed system is reachable, partition states match expectations, retired systems are removed. NOT_ASSESSED if you have not independently verified network reachability.

## 5. Console backups — can you recover the HMC itself?

Check for a recent, verified console backup (`mkconsbackup` or the web UI **Console Backup** page). Verify the backup file exists, has a reasonable size, and is stored off-appliance.

**Why it matters:** the HMC is the single point of control. If the appliance fails with no usable backup, the entire Power estate may be unrecoverable — even though the AIX partitions are perfectly healthy.

**What good looks like:** a recent backup (within 30 days or consistent with your change cadence), stored off-appliance, with a reasonable file size. NOT_ASSESSED if backup storage is not independently verified.

## Why the HMC earns its own pass

Every AIX audit focuses on the partitions — the operating system, filesets, storage, security. That is where AIXray shines. But the HMC is the control plane beneath those partitions. You can have a perfectly patched, resilient LPAR that no one can boot or recover without the HMC. The HMC is a single point of control by design, and that earns a dedicated audit pass.

## What AIXray does and does not cover

AIXray is a free, open-source (Apache-2.0), read-only assessment that runs on each AIX and VIOS partition — covering lifecycle currency, patch gaps, storage, resilience, error history, security, configuration hygiene, and monitoring.

AIXray does not run on the HMC. This is not a gap; it is a scope decision. The HMC is a distinct platform with its own command set and failure modes. The honest approach is two passes: AIXray for partitions, this manual checklist for the HMC.

Run AIXray on every partition, walk through this checklist on every HMC. The evidence belongs together even if the tools are different.

## If you'd rather have it fixed

Running the HMC checklist and AIXray gives you evidence from both sides of the Power estate. Acting on it is the harder part. AIXray is made by [PowerTrue Systems](https://powertruesystems.com), a managed-services firm run by senior AIX/Power engineers — so if your combined audit surfaces things you would rather not carry alone, we can help. AIXray is free and open source; PowerTrue can serve as your managed-service partner or stay in the background. Visit [https://powertruesystems.com/aixray](https://powertruesystems.com/aixray) or [https://github.com/PowerTrueSYS/aixray-public](https://github.com/PowerTrueSYS/aixray-public) to get the tool and review the source before you run it.
