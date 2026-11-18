# Local snapshot import

The Windows Core imports individual files from explicitly authorized directories. It does not chat, advertise or grant a remote peer access as a side effect. Network publication and leases require their own later policy checks.

## From source to reference

1. The local user selects a directory, extensions, audience and logical byte limit. The broker stores the NTFS volume and directory identity; a path alone cannot restore the grant. Model access defaults to `never`.
2. `SnapshotBroker::import_source` restores the directory capability and opens one stable source handle. It checks length and reserves capacity in an immediate SQLite transaction **before the first content read**. This is an import of a *new* resource; it does not fabricate a T07 disclosure permit.
3. The broker copies and hashes in protocol-sized chunks, produces the existing ASL manifest format and synchronizes content and manifest. Installation compares existing objects byte for byte on deduplication. File-sized work runs outside the SQLite writer lock.
4. A short transaction checks the grant epoch, task, expiry and current limits, binds the ready snapshot to a local resource, and consumes the reservation. A resource key can be returned only after commit. A second grant gets its own resource key and audience even when the disk objects are identical.
5. Revocation invalidates only references owned by the affected grant. A change to an imported path invalidates its old reference; changing it back does not automatically reauthorize or reimport it.

## Limits and scope

- The global budget accounts for each stored blob and manifest once and reserves space for staging **and** installation. A grant is charged for its own active logical references. Reimporting requires staging headroom even when the final result deduplicates.
- Budgets come from trusted local settings, not a peer or model. The defaults are 20 GiB globally and 1 GiB per import task. These are byte budgets, not physical allocation guarantees; NTFS metadata and SQLite use additional space. Disk-full errors cannot make a new ready reference.
- Core watches up to 64 distinct authorized roots with active imports. Notifications schedule checks of known local references, not discovery of arbitrary new files. A monotonic 30-second timer covers lost notifications and unwatched roots. The interval starts work; it does not promise an entire library is hashed within 30 seconds.
- Reconciliation uses file identity, length and content hash, not just the name or modification time. Checking a large library costs disk reads. A background check is not a freshness guarantee at the time of a later transfer. The transfer path must independently recheck the current binding and recipient before issuing or using a lease.
- SQLite schema v2 extends v1 in place. A v1 local reference with no recorded import epoch is retained but made inactive; a fresh authorized import is required. Existing settings, identities and grants are not recreated.

Implementation: `crates/asl-app/src/libraries.rs` (Core lifecycle), `crates/asl-store/src/resources/` (authority and transactions), `crates/asl-policy/src/snapshot_files.rs` (disk objects) and `crates/asl-policy/src/reconcile.rs` (local change detection).

## Interrupted imports

Staging files use Windows delete-on-close. A durable, per-content installation claim excludes other installers while the final pair is prepared; an exclusive per-reservation handle distinguishes a live importer from one that exited. Without a durable snapshot row the two destination names must both be absent before a new claim is committed. Unknown pre-existing files are not adopted or deleted.

Startup and periodic reconciliation try expired imports in bounded pages. A live owner, ambiguous filesystem result or blocked cleanup does not free the budget. When there is no durable reference and the original owner is gone, recovery cleans only the two derived names and releases the reservation. A durable snapshot row protects the pair regardless of the status of the failed import. These guarantees cover process termination on a working local NTFS volume; they are not a power-loss or storage-hardware certification.
