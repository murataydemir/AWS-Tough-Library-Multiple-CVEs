### <b>AWS Tough Library Multiple CVEs</b>
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
In March 2025, multiple security vulnerabilities were disclosed in AWS Labs’ <b>Tough</b> library (a Rust client implementation of TUF – The Update Framework). These issues are tracked under CVE-2025-2885, CVE-2025-2886, CVE-2025-2887 and CVE-2025-2888, and were fixed in [Tough version 0.20.0](https://aws.amazon.com/security/security-bulletins/AWS-2025-007/#:~:text=AWS%C2%A0is%20aware%20of%20the%20following,to%20incorporate%20the%20new%20fixes). Security engineers can use this document to understand each vulnerability’s technical details, root cause in the codebase, and the patches that resolve them. All users of Tough < 0.20.0 are strongly advised to upgrade to v0.20.0 or later​.

#### CVE-2025-2885: Missing Sequential Root Version Validation
Tough failed to validate the `Root metadata` version in sequence during update. An attacker controlling a repository (or with man-in-the-middle ability) could supply a root metadata file with an unexpected version number, causing the client to fetch and trust a wrong version​. In essence, Tough did <b>not ensure that a new root metadata’s version was exactly one greater than the previously trusted version</b>, violating TUF’s requirement for a continuous chain of trust. This could lead to <b>rollback or mix-and-match attacks</b>, where an old (but properly signed) root is accepted as if it were the latest, potentially <b>re-introducing retired signing keys or expired trust</b>.

- <b>Advisory:</b> [GitHub Security Advisory GHSA-5vmp-m5v2-hx47 (CVE-2025-2885)](https://github.com/advisories/GHSA-5vmp-m5v2-hx47)
- <b>Affected Code:</b> Tough’s update logic for root metadata in `tough/src/lib.rs`. The vulnerable implementation only checked that the new root’s version was not less than the old one, instead of requiring it to be the next sequential version​. This omission breaks the TUF spec’s rule that clients must download intermediate root versions in order (no version skipping).

<b>Vulnerable Implementation:</b> In version 0.19.x and earlier, after downloading a new `root.json`, Tough verified signatures but did not strictly enforce the version continuity. It permitted [the new root version to be any value >= the trusted version](https://github.com/awslabs/tough/commit/0eeb60aefe27f00b65730634b788a1aafb8bf3c6). For example, if the current trusted root was version N, Tough would accept a new root claiming version N+2 or higher (as long as signatures were valid), skipping N+1. The code snippet below illustrates the check prior to the fix:

```rust
// (Prior to fix) Allow new root version to be >= old version – too permissive
ensure!(root.signed.version <= new_root.signed.version, error::OlderMetadataSnafu { 
    role: RoleType::Root, 
    current_version: root.signed.version, 
    new_version: new_root.signed.version 
});
```

An attacker could exploit this by presenting <b>a higher-version root metadata that is actually an older key set</b>. Tough would accept it, thinking it’s an update, and [trust content signed with outdated keys](https://github.com/advisories/GHSA-5vmp-m5v2-hx47#:~:text=The%20tough%20client%20will%20trust,with%20a%20previous%20root%20role).

<b>Fixed Implementation:</b> The patched code (in Tough 0.20.0) explicitly requires the new root’s version to be exactly one greater than the old version, see [commit 0eeb60a](https://github.com/awslabs/tough/commit/0eeb60aefe27f00b65730634b788a1aafb8bf3c6). It also ensures the new version is higher (prevents equality or decrease) and prevents any jump larger than +1:

```rust
// (Fixed in v0.20.0) Enforce sequential root version update (new_version == old_version + 1)
ensure!(
    root.signed.version < new_root.signed.version && 
    root.signed.version.get() + 1 == new_root.signed.version.get(),
    error::OlderMetadataSnafu { 
        role: RoleType::Root, 
        current_version: root.signed.version, 
        new_version: new_root.signed.version 
    }
);
```

This change ensures the client downloads and applies root metadata in order (N, N+1, N+2, ...) without skipping. If a root metadata file is encountered with a version not exactly old_version+1, Tough now treats it as a potential attack and aborts the update.
- <b>Root Cause:</b> Missing sequential version check (CWE-1288: Improper Validation of Integrity Check Value) The code only guarded against new root being older than current, but not against unexpected jumps.
- <b>Remediation:</b> Upgrade to tough <b>= 0.20.0</b>, which includes the patch. Ensure any forks or custom updaters based on Tough implement the same strict check. It’s also wise to audit logs for any suspicious root version jumps in update history as an indicator of attempted exploitation.

#### CVE-2025-2886: Terminating Delegation Not Respected
Tough mishandled <b>“terminating” delegated targets roles</b> as defined by TUF. In a TUF repository, a delegation can be marked <i>terminating</i>, meaning that if a target lookup reaches that delegation and the target is not found there, the search should stop (and not continue to other lower-priority delegations)​. (see [here](https://github.com/advisories/GHSA-v4wr-j3w6-mxqc#:~:text=Terminating%20delegations%20and%20delegation%20priority,that%20should%20have%20been%20ignored)) Due to a logic error, Tough <b>failed to terminate the search</b> in this case – it would continue searching subsequent delegations even when it should have stopped. This could allow an attacker controlling a lower-priority delegation to serve content for targets they shouldn’t control, [bypassing the intended trust boundaries](https://github.com/advisories/GHSA-v4wr-j3w6-mxqc#:~:text=When%20interacting%20with%20TUF%20repositories,owned%20by%20the%20delegating%20identity).​

- <b>Advisory:</b> [GitHub Security Advisory GHSA-v4wr-j3w6-mxqc (CVE-2025-2886)​](https://github.com/advisories/GHSA-v4wr-j3w6-mxqc)
- <b>Affected Code:</b> The target lookup algorithm in `tough/src/editor/targets.rs` (and related delegation resolution code). The vulnerable code did not properly handle the `terminating` flag on delegations. When iterating through delegations in search of a target, Tough would proceed to the next delegation even if the current one was marked terminating and had no match, contrary to the TUF spec.

<b>Vulnerable Implementation:</b> In Tough <0.20.0, the `find_target()` logic simply recursed or looped through all possible delegated roles until a target was found or all were exhausted. It did not set any flag or break out when encountering a terminating role. Pseudocode of the old behavior:

```rust
for role in delegation_chain {
    if role.has_target(target) {
        return target_metadata;
    }
    // Missing: if role is terminating and target not found, should break.
    // Tough erroneously continues to next delegation.
}
```

This means a lower-priority delegate (which should be ignored after a terminating delegation above it) could still be consulted and supply a malicious target file​

<b>Fixed Implementation:</b> The patched version introduces a mechanism to track termination and stop the search appropriately. When a terminating delegation is encountered and does not contain the target, Tough now [breaks out of the search loop immediately](https://github.com/awslabs/tough/commit/598111f88105a707ee68b0fa06c52da7176ea96a#:~:text=%2F%2F%20we%20encountered%20a%20terminating,so%20we%20stop%20iterating%20immediately). In the updated code, a boolean flag (e.g. `terminated`) is set when a terminating role is hit, and propagated up the call stack. For example:

```rust
// If a terminating delegation was reached (and we didn't find the target there), stop searching further
if role.terminating && !permissive {
    // Mark that we encountered a terminating delegation
    *terminated = true;
    break;
}
```

Additionally, the recursive `find_target` calls now carry a `terminated` flag to ensure that once termination is signaled, [no other delegations are considered in higher-level loops​](https://github.com/awslabs/tough/commit/598111f88105a707ee68b0fa06c52da7176ea96a). Tough’s `RepositoryEditor::delegate_role` and related structures were also updated to <b>store the `terminating` attribute</b> and pass it through the search logic.
- <b>Root Cause:</b> A logical flaw where the code did not implement the terminating delegation semantics (CWE-284: Improper Access Control – lower-priority roles could override intended restrictions)​. Essentially, the absence of a `break` on a terminating delegation allowed unauthorized target data to be considered.
- <b>Impact:</b> Clients could fetch targets owned by the wrong role – specifically, if a project delegated a subset of targets to another party (and marked that delegation as terminating to limit override scope), that party could still serve arbitrary content for targets outside its scope. This breaks trust hierarchies in a TUF repository.
- <b>Remediation:</b> Update to tough <b>0.20.0+</b> which correctly implements terminating delegation handling. If you maintain a fork or custom client, ensure that your target lookup halts on terminating delegations. Security testers should attempt delegation abuse scenarios only on older versions; the patched version will correctly ignore malicious lower-priority responses.

#### CVE-2025-2887: Incomplete Rollback Detection for Delegated Targets
Tough’s logic for detecting <b>rollback attacks in snapshot metadata</b> was incomplete. Specifically, when updating the Snapshot role, Tough should verify that <b>all previously seen targets metadata (including delegated targets) are still present and not versioned backwards in the new snapshot</b>. (see [here](https://github.com/advisories/GHSA-q6r9-r9pw-4cf7#:~:text=When%20updating%20the%20snapshot%20role%2C,check%20for%20delegated%20targets%20files)) Tough did enforce this for the top-level `targets.json`, but <b>failed to do so for delegated target metadata files</b>. This gap could allow an attacker to remove or revert a delegated target file in the repository’s snapshot metadata without detection, [causing the client to accept an outdated (or missing) delegated target file as if it were up-to-date](https://github.com/advisories/GHSA-q6r9-r9pw-4cf7#:~:text=tough%20could%20fail%20to%20detect,targets%20that%20it%20should%20reject)​.

- <b>Advisory:</b> [GitHub Security Advisory GHSA-q6r9-r9pw-4cf7 (CVE-2025-2887)](https://github.com/advisories/GHSA-q6r9-r9pw-4cf7)
- <b>Affected Code:</b> The snapshot update verification in `tough/src/lib.rs` (function that loads/applies new Snapshot metadata). The vulnerable code only checked the continuity of the main `targets.json` role in the snapshot, but <b>did not iterate over delegated roles</b> listed in snapshot metadata to perform similar checks.

<b>Vulnerable Implementation:</b> In Tough <0.20.0, after retrieving a new `snapshot.json`, the client would ensure that the root and snapshot roles were not rolled back, and it would specifically ensure that `targets.json` was still present. It also verified that the version of `targets.json` in the new snapshot was >= the previous version. However, <b>if the snapshot contained delegated targets (e.g., `projects.json`, `user.json` delegated metadata)</b>, the client did not verify those. For example, originally the code did something like:

```rust
// Pseudo-code of original snapshot rollback check (simplified)
if let Some(old_targets_meta) = old_snapshot.meta.get("targets.json") {
    let new_targets_meta = new_snapshot.meta.get("targets.json").unwrap();
    ensure!(new_targets_meta.version >= old_targets_meta.version, ...);
}
// (No checks for delegated target roles like "projects.json", "user.json", etc.)
```

This means if an attacker with repository access <b>removed a delegated metadata file or rolled it back to an older version</b>, Tough’s client would not notice – as long as the primary targets.json was intact. The client could then download an outdated target from that delegation, unaware that it should have been rejected as a rollback.

<b>Fixed Implementation:</b> Version 0.20.0 adds comprehensive checks for <b>every role listed in the snapshot metadata</b>. The new code iterates through each entry in the old snapshot’s metadata (including all delegated targets roles) and ensures two things for each: (1) that the role still exists in the new snapshot, and (2) its version has not decreased. If any role is missing in the new snapshot or has a lower version number than before, the update is rejected as a potential rollback attack​. For example:

```rust
for (name, old_meta) in &old_snapshot.signed.meta {
    // 1. Role must appear in new snapshot
    ensure!(
        snapshot.signed.meta.contains_key(name),
        error::SnapshotRoleMissingSnafu { role: name, old_version: old_snapshot.signed.version, new_version: snapshot.signed.version }
    );
    // 2. Role’s version must not decrease
    let new_meta = snapshot.signed.meta.get(name).unwrap();
    ensure!(
        old_meta.version <= new_meta.version,
        error::SnapshotRoleRollbackSnafu { role: name, old_role_version: old_meta.version, new_role_version: new_meta.version, … }
    );
}
```

By looping through <b>all roles</b> (name represents each metadata filename like `targets.json`, `delegated-role.json`, etc.), the client will catch if any delegated target metadata was removed or reverted. The errors `SnapshotRoleMissing` and `SnapshotRoleRollback` will trigger [if a role disappeared or its version went backwards](https://github.com/awslabs/tough/commit/3345151a87c358d1ce43aeb7e8b3ebea5ebdbab4). Notably, Tough now also explicitly ensures that the snapshot contains at least the `targets.json` entry (otherwise it errors with `SnapshotTargetsMetaMissing`) as a sanity check​.

- <b>Root Cause:</b> Incomplete verification – Tough did not apply rollback checks uniformly to delegated target roles. This is a <b>partial implementation of a security control</b>, leaving a gap that attackers could exploit (CWE-352: Missing Crucial Step in Authorization; conceptually a subset of integrity verification issues). The code was only protecting top-level targets, assuming (incorrectly) that delegated roles wouldn’t regress.
- <b>Impact:</b> An attacker able to manipulate the repository could hide updates or re-introduce old delegated target data without client detection. For instance, they could present an older delegated targets file signed with a now-compromised key, and because Tough didn’t check that file’s version, it would be accepted. In practice, this could result in clients <b>fetching outdated content</b> or missing critical revocations for delegated targets​. (see [here](https://github.com/advisories/GHSA-q6r9-r9pw-4cf7#:~:text=tough%20could%20fail%20to%20detect,targets%20that%20it%20should%20reject))
- <b>Remediation:</b> Use tough <b>v0.20.0+</b>, which implements full snapshot rollback checking​. If maintaining a custom updater, ensure that for <b>every trusted metadata file</b> listed in a snapshot, the new snapshot also lists it with a version number >= the previous version. It’s also recommended to enable logging or auditing for any <b>delegated targets removals</b> in repository updates, as these should be rare and might indicate malicious activity if occurring unexpectedly.
