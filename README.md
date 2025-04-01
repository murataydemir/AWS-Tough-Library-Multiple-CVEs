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
