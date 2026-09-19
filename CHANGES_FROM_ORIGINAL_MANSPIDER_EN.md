# Differences Between the Current Version and the Original MANSPIDER

## 1. Startup, Scan Scope, Filters, and Authentication

| What changed | Brief explanation | Benefit | Example or important clarification |
| --- | --- | --- | --- |
| Credentials are now mandatory for SMB | A network scan requires an explicit username and password/hash, or Kerberos. Credentials are not required when scanning only a local directory. | An accidental anonymous scan cannot start in place of the intended domain credential check. | `manspider host -u alice -p secret ...`; the local command `manspider /data ...` works without credentials. |
| A separate credential preflight was added | SMB targets are checked in random order before traversal. One successful login is sufficient; credentials are declared invalid only after three definitive rejections, or rejections from every target when there are fewer than three. | Incorrect credentials are detected through a bounded check before large-scale traversal. | Host A is unavailable, B rejects the credentials, and C accepts them—the main scan becomes eligible to start, subject to operator approval. The preflight itself creates an authentication session, after which the main scan creates its working sessions. |
| Preflight does not use guest or null sessions | The preliminary stage checks the supplied identity specifically. Guest or null sessions remain only a normal fallback for the main scan after at least one success. | Guest access is no longer treated as validation of domain credentials. | Silent mapping of a domain user to guest access is treated as a rejection of the supplied identity. |
| Connection errors are distinguished from authentication rejections | An unavailable host is not counted as having rejected the credentials and is replaced with another where possible. Defaults allow 10 seconds per host and 300 seconds overall. | A network failure does not produce a false “incorrect password” conclusion. | Configurable through `--preflight-timeout` and `--preflight-time-budget`. More than three addresses may be checked, but there are no more than three definitive authentication rejections. |
| Share observations are reused | An already established successful session provides a bounded estimate of share count for the large-infrastructure policy; no separate full inventory is built. | The preliminary stage performs less repeated SMB work. | For a large scope, the policy is determined before scanning, while the object manifest then fills incrementally. |
| Main-scan authentication failures are isolated by host | A rejection from an individual Windows/Linux/Samba endpoint is recorded as a local outcome and does not stop other hosts. | A mixed scope is not interrupted by a server that does not accept domain credentials. | There is still no default `--max-failed-logons` limit; an explicit `-mfail N` preserves the previous option. |
| Additional workers do not multiply the initial rejection | The authentication outcome for the supplied identity and the selected fallback mode are determined and passed to the workers before parallel sessions are created. | Each worker does not generate another domain login already known to fail. | This is not an absolute ban on reauthentication after reconnects or session expiry; it eliminates the normal repetition of an already known rejection. |
| Kerberos preparation was strengthened | The `FILE` cache is checked before scanning; a plain path and the `FILE:` prefix are accepted, while other cache types are rejected. For an IP-address target, hostname discovery for the SPN and an explicit `-dc-ip` are supported. | Kerberos errors are detected earlier, and IP-address targets work more reliably with tickets and SPNs. | Passwords, hashes, AES, and Kerberos were already supported upstream; parameter validation and verified usage scenarios have changed. |
| Command-line validation was strengthened | Regular expressions, dates, the AES key, numeric limits, conflicting format policies, rules, resumption, and overlapping report paths are checked before the main scan. | Configuration errors are not discovered only after network activity has begun. | An extension present in both `--read-formats` and `--skip-formats` is rejected immediately. |
| Effective configuration output was added | Normalized targets, filters, exclusions, rules, policy, the state database, and auxiliary reports are shown before scanning. | The user can see the effective scope and spot a mistake before traversal. | Full credentials and secrets are not masked, as required by the project. |
| Main scanning requires explicit approval | After preflight, the operator reviews the final effective scan configuration and must approve the main scan on every invocation, including resume. `-y` / `--yes` supplies approval for automation. | Traversal does not start before the operator accepts the effective scope and settings. | Preflight has already performed bounded authentication and share queries; this is approval before the main scan, not a guarantee of zero network activity before approval. |
| Filters were consolidated into a single `ScopeMatcher` | OR applies within each category and AND between active categories; `--or-logic` changes the relationship between categories to OR. | Behavior is the same for local and network scans and no longer depends on where a filter is checked. | By default, `-f pass -e txt` requires a matching filename AND extension; with `-o`, either is sufficient. |
| Content filters participate correctly in OR logic | A file that may still match by content is not discarded prematurely merely because its name or extension does not match. | `--or-logic` genuinely considers content, not just metadata. | `report.log` is still read if an active content condition can bring it into scope. |
| Traversal through a nonmatching parent directory was fixed | A directory include filter no longer stops traversal at the parent, because a matching descendant may exist deeper in the tree. An exclude filter, by contrast, prunes the entire subtree. | Silent omissions of nested secrets are eliminated. | `--dirnames secrets` reaches `ordinary/team/secrets` even though `ordinary` itself does not match. |
| Default traversal depth was increased | The default `--maxdepth` value was raised from 10 to 15; an explicit `-m N` still takes precedence. | More deeply nested directories are included in an ordinary scan without an additional option. | A deeper limit can expand traversal work on shares with deep directory trees. |
| Exclusions now have unconditional priority | A share, directory, or file excluded by an explicit filter cannot re-enter scope through OR logic. The reason is recorded separately from the `skipped` status. | Negative constraints are predictable and testable. | An excluded subtree is counted separately and does not receive a misleading `skipped` status. |
| Share enumeration excludes non-file and unknown SMB types | In addition to the previous four names, selection checks `shi1_type` returned by share enumeration and admits only a known disk-share base type. | Resources identified as printers, IPC, other non-file types, or unknown types do not enter ordinary traversal through this selection step. | `IPC$`, `PRINT$`, `C$`, and `ADMIN$` were already excluded upstream. This is an enumeration filter, not validation of the actual type of every connection, including DFS destinations; its precise boundaries are explained below. |
| Precise control over default exclusions was added | `--add-exclude-sharenames` appends to the list, `--allow-sharenames` restores an individual name, and `--no-default-share-exclusions` disables default name-based exclusions. The existing `--exclude-sharenames` still replaces the entire list. | There is no need to choose between a rigid default list and a fully manual one. | `C$` alone can be restored without also enabling `IPC$` and `PRINT$`. |
| Size boundaries and empty-file handling changed | A file whose size exactly equals `--max-filesize` is allowed; an empty file is not discarded before metadata and rule evaluation. | Metadata rules can detect empty credential files, and the limit boundary is intuitive. | The default size limit remains unchanged at 10 MiB. |
| Saving matched files became an explicit choice | Permanent copies are no longer saved by default; `--download` is required. The obsolete `-n` and `--no-download` options have been removed. | Metadata-only searches avoid unnecessary content transfers and accumulated copies of findings. | Content rules still read the data they require; `--loot-dir` alone does not enable downloads. |
| Metadata findings are no longer subject to the global file-size limit | `-s` limits content reads and optional downloads, not reporting by filename, extension, or other metadata. | Large backups and virtual-machine disks are no longer lost from the results. | A 100 GiB `.vmdk` is reported without reading it; mixed rules retain metadata findings while content analysis is marked as size-skipped. Size predicates within an individual rule still apply. |
| A large-infrastructure policy was added | Scope is classified by host count and a bounded share estimate: defaults are 256 hosts or 1 024 shares. Non-text content can automatically be left unread in a large scope. | Across hundreds or thousands of shares, expensive archive, image, and binary reads are reduced while metadata findings are preserved. | `--large-domain-mode auto/always/never`, along with `--large-domain` and `--no-large-domain`. |
| Explicit control over format policy was added | `--non-text-policy`, `--read-formats`, and `--skip-formats` override automatic representation selection. | Users can improve coverage of required formats or deliberately reduce expensive extraction. | `--read-formats png zip` enables OCR and archives even for a large infrastructure. |
| Scope filters are separate from rules | Filters determine whether an object falls within the user's scope; rules determine findings and required representations. | A rule-local optimization cannot silently change the user's scope. | A matching metadata rule can produce a finding without content analysis. |

### What specifically changed in SMB share-type filtering

When SMB shares are enumerated, the server returns not only each share's name
but also the numeric `shi1_type` field. The lower part of this value describes
the share's primary purpose: `0` is a disk file tree, `1` is a print queue, `2`
is a device, and `3` is interprocess communication (IPC). Original MANSPIDER
made its decision primarily from the name. If a share was not named `IPC$`,
`PRINT$`, `C$`, or `ADMIN$`, the scanner could try to open it as a directory
regardless of its actual type.

The current version first applies name exclusions and then checks the type
reported by share enumeration. This selection step admits only the file-share base type
`0`. Additional high-order flags, such as the special or hidden administrative
share flag, do not turn a file share into a non-file share.

Practical examples:

- `OfficePrinter` is absent from the default name-exclusion list, but the server
  reports type `1`, meaning a print queue. The original version could issue a
  pointless share connection (`TREE_CONNECT`) and directory-listing attempt;
  the current version excludes it before that traversal;
- `ApplicationPipe` with type `3` is an IPC endpoint even though its name does
  not end in `$`. It is also excluded by type;
- `Archive$` with file type `0` and a special-share flag remains a valid file
  share: the `$` character alone is not an exclusion reason;
- `C$` normally has file base type `0`, but it remains excluded by name by
  default. `--allow-sharenames C$` can restore it to scope, whereas allowing the
  name of an actual print queue does not change its non-file type;
- `PRINT$` is often a file share containing printer drivers rather than the
  print queue itself. It remains excluded by its default name, while a separate
  queue such as `OfficePrinter` is filtered by type.

An exclusion does not disappear silently. The state database retains the share
name and a reason such as `non-file SMB type 1`, and the exclusion counter is
incremented. A user can therefore distinguish an intentionally skipped print
queue from a file share that the scanner tried and failed to read. If the server
did not report a type—for example, for an explicitly named hidden share absent
from the enumeration response—the share is excluded with the reason
`unknown SMB type`, rather than assumed to be a file share.

This filter uses enumeration metadata (`shi1_type`), not the actual resource type
returned by `TREE_CONNECT`. A separate check of that response, including the final
target of a DFS referral, has not been implemented. Enumeration filtering therefore
does not guarantee that every later connection is to a disk resource. Restricted
`IPC$` operations for share-enumeration RPC and DFS referrals are intentional
service operations and remain permitted.

## 2. Rule Engine and Built-in Rule Pack

| What changed | Brief explanation | Benefit | Example or important clarification |
| --- | --- | --- | --- |
| A versioned rule engine was created | JSON schema versions 1, 2, and 3 and a normalized internal representation were added. Original MANSPIDER supported only regular expressions and wordlists from the command line. | Rules can be versioned, tested, composed, and saved with scan state. | None |
| Compatibility with simple JSON rules was preserved | A simple object with `id`, `pattern`, `flags`, `description`, and `enabled` is treated as a content-regex rule. | Older intermediate packs do not need to be rewritten immediately. | Such a rule is normalized into the same model as schema version 3. |
| Metadata predicates were added | Rules can check the share, path or directory, filename, compound extension, size, and modification time before reading content. | Content analysis runs only for rules that require it; a metadata candidate does not force the parser to extract text. | `.kdbx` can become a metadata finding without parsing the database. Only an explicit `--download` permits retrieving the file solely to save a copy, within the size limit. |
| Condition operators were expanded | `exact`, `contains`, `startswith`, `endswith`, `regex`, ranges, negation, and explicit `all` and `any` are supported. | Complex rules are expressed declaratively, without Python plugin code. | A rule can require the path to match `contains .aws` and the filename to match `exact credentials`. |
| The `report`, `scan`, and `inspect` actions were added | `report` creates a metadata finding, `scan` requests a representation and evaluates content predicates, and `inspect` runs one of the fixed structured inspectors. | Low-cost candidates, text search, and evidence-based structural validation are separated. | The action determines what evidence is required after a rule's conditions match. An unknown action such as `http` or `exec` is rejected before scanning. A detailed explanation follows below. |
| Minimal representation selection was implemented | Before retrieving a file, the engine determines which representations are required: `text`, `strings`, `raw`, `ocr`, and `structured`. Each representation is extracted no more than once per file. | Multiple rules share extracted data without duplicating SMB reads or parsing. | Ten text rules do not mean ten downloads of the file. |
| Representation errors are isolated | An OCR, structured extraction, or individual rule error does not remove findings already obtained from other representations. | Useful partial results are not lost because of a single decoder. | A raw-data finding is retained even if OCR fails for the same file. |
| Findings now have full provenance | The rule identifier, source, and schema; pack identifier and version; representation; exact value, context, and offset; and network path are recorded. | Results are reproducible, and their origin is clear. | The same value at two JSON pointers remains two separate pieces of evidence. |
| Independent classification was added | A finding has `severity`, `confidence`, `category`, and `tags` fields. | A confirmed secret can be distinguished from a candidate filename, public identifier, or encrypted material. | A broad keyword receives a low confidence score, while an exact service-specific signature receives a higher one. |
| Rule-local exclusions were added | A negative condition suppresses only the current rule; it neither removes the object from scan scope nor blocks other rules. | Noise is reduced without introducing global blind spots. | A placeholder can be excluded from a password rule while still matching a private-key rule. |
| Rule-pack composition was added | `--rules` accepts multiple files; `--rule-overrides` explicitly replaces a rule by identifier; `--disable-rules` disables exact identifiers. Collisions and unknown controls are treated as errors. | The pack can be customized without implicit dependence on overwrite order. | Changing rules or the pack requires new compatible scan state; an existing scan cannot silently resume with different rules. |
| An explicitly enabled built-in pack was added | `manspider.default@2.7.0` contains 251 native rules and is enabled with `--builtin-rules`. | Most typical searches can run without huge manually maintained `-e`, `-f`, and `-c` lists. | The pack does not activate automatically: starting without filters or rules is still rejected. |
| The user's first legacy command is covered | The pack covers 102 extensions and 66 canonical filename alternatives, including one trailing suffix under the legacy filename-stem semantics. | A long command for locating interesting files can be replaced with a testable pack. | Coverage includes secret stores, 1C, databases, virtual machines and backups, mail and notes, archives, certificates, SSH, the registry, and developer configurations. |
| The user's second legacy command is covered | The 22 content signals apply to all 55 required extensions. | Expected content search is preserved without manually copying dozens of regular expressions. | Coverage includes Russian and English credential assignments, connection strings, keys, and service-specific tokens. |
| Overlapping signals are no longer hidden | Broad and service-specific matches remain separate findings; neither displaces the other. | Neither general context nor more precise classification is lost. | A generic token rule and an exact GitLab token rule can both match. |
| Modern credential categories were added | Coverage was expanded for cloud services, CI/CD, containers, package registries, SaaS/API clients, LDAP/SSSD, Kafka/JAAS, deployment tools, and network services. | Secrets in modern stacks that were absent from the original command-line set can be found. | AWS, GitHub/GitLab, Slack, Kubernetes, registries, Terraform, and other families. |
| Existing content detectors were strengthened | Handling was refined for quoted JSON/YAML keys, multiline and prefixed assignments, AWS boundaries, Ansible Vault, HTTP authentication headers, Redis/SQLAlchemy URIs, and XML namespace and CDATA cases. | Coverage of real configurations improves without simply broadening a generic keyword regex. | Exact match spans for old and new variants are covered by differential test fixtures. |
| False high-specificity signals were reclassified | Public SSH material, ordinary configurations, Unix account inventories, the Twilio identifier, commands without passwords, and encrypted WLAN material are no longer presented as confirmed plaintext secrets; netrc, npm, SQL, Vault, and WireGuard rules were strengthened. | Less high-confidence noise while preserving metadata candidates and relevant files. | A public identifier may remain a useful candidate, but it is not classified as a password. |
| Rules for editor, session, and workspace state were added | Coverage includes Sublime Text (`.sublime_session` and recovery data), VS Code/VSCodium/Cursor, JetBrains, Vim/Neovim, Emacs, Notepad++, Kate, Visual Studio, Xcode, and Eclipse. | Temporary editor-state files often contain paths, commands, history, and secrets missed by ordinary configuration searches. | A generic `workspace.xml` requires an editor-specific path to reduce noise. |
| A private-key inspector was added | It locally distinguishes PEM/OpenSSH/DER/PKCS#12 private-key material from a public certificate; it can also test a bounded set of rule-configured container passwords. | A public certificate is not labeled as a private key, and findings for genuine key containers include more precise evidence. | This is local byte parsing, not an attempt to log in anywhere. |
| A Kubernetes Secret inspector was added | JSON is parsed with fields bound to their owning resource, `stringData` precedence, Base64 decoding, and exclusion of entirely public material. | Secrets are not merged with a neighboring ConfigMap or another document. | The discovered value is retained in full and is not sent to the Kubernetes API. |
| AD/GPP inspectors and rules were added | Coverage includes NTDS/IFM, registry hives, SYSVOL/GPO/NETLOGON, Kerberos, AD CS, ADFS/Entra Connect, LAPS/BitLocker, and Samba AD; LDIF/JSON and GPP XML are parsed structurally. | A finding is bound to its own object or attribute, and GPP `cpassword` can be safely decrypted locally. | DTDs and external entities are prohibited; URLs and UNC paths from LDIF are not dereferenced; no LDAP, DCSync, or API requests are made. |
| Russian-language search was added | Russian filenames and labels, morphology, `е/ё`, case handling, placeholders, and distinctions between login names, public identifiers, and secrets were strengthened. | Localized credential documents and configurations not covered by English keywords can be found. | Pack 2.7 strengthened 23 definitions and added three new identifiers. |
| Cyrillic and Unicode decoding was expanded | UTF-8/16/32, escaped Unicode in JSON, and explicit CP1251/CP866/KOI8-R candidates are checked without additional network reads. | This reduces the risk of missing a secret because of short text or a legacy encoding. | An ambiguous legacy encoding remains an explicitly classified candidate. |
| Ambiguous formats and backup formats were fixed | For `.key`, Keynote ZIP files, Rails `master.key`, and key material are distinguished; for `.bak`, `.old`, and `.orig`, the original format and its processing policy are considered. | The wrong extractor does not hide a text secret, and a backup does not bypass a restriction on its actual container type. | `archive.zip.bak` requires ZIP to be allowed, not just the `bak` suffix. |
| Rules run entirely locally | Packs are read from disk, and regular expressions and inspectors operate on bytes already obtained; discovered credentials are neither validated through network login nor used. | Scanning does not send secrets to the Internet or create unexpected connections based on a finding. | The network is used only for normal SMB scanning of the scope, the selected authentication method and any required Kerberos/DNS traffic, and explicitly permitted external DFS referrals. |

### Why rules need the `report`, `scan`, and `inspect` actions

The `match` and `exclude` conditions answer only whether a rule applies to a
particular file according to metadata already available. An action answers a
different question: what evidence must be obtained after that decision. This
separation prevents every candidate file from being treated as a confirmed
secret and avoids reading content when a filename or extension is sufficient.

#### `report`: record a metadata candidate

`report` is used when the existence of a file with a particular name,
extension, or path is already interesting. The action does not require file
content. The resulting finding contains the complete file path and states that
metadata conditions matched.

For example, a rule can treat every KeePass database as a useful candidate:

```json
{
  "id": "keepass-database-file",
  "match": {
    "predicates": [
      {"field": "extension", "operator": "exact", "value": ".kdbx"}
    ]
  },
  "actions": [{"type": "report"}]
}
```

The file `\\server\finance\archive\team-vault.kdbx` is reported even when the
database is encrypted and its internal content cannot be examined. This means
“a potentially important file was found,” not “a password inside was
confirmed.” If no other matching rule requires `scan` or `inspect`, the file
is neither read nor saved by default. Only an explicit `--download` permits
retrieval within the size limit for placement in the local `loot` directory,
even though the `report` action itself does not require the bytes.

#### `scan`: find an exact match in a selected representation

`scan` is needed when metadata is insufficient and content must be checked.
After `match` succeeds, the file is read, converted once into the requested
representation, and evaluated with a regular expression or predicate group.
The actual value, context, and offsets are retained for every match.

For example:

```json
{
  "id": "environment-assigned-password",
  "match": {
    "predicates": [
      {"field": "filename", "operator": "startswith", "value": ".env"}
    ]
  },
  "actions": [
    {
      "type": "scan",
      "representation": "text",
      "pattern": "(?im)^password\\s*[:=]\\s*[^\\r\\n]+$"
    }
  ]
}
```

For `.env.production` containing `PASSWORD=RealSecret!`, the result retains the
exact line and its match position. This rule does not route `manual.pdf` to
analysis because its filename did not pass `match`.

The representation controls how the inspected data is obtained:

- `text` is ordinary text or compatible text extraction from a known document;
- `strings` contains printable strings from a binary file;
- `raw` is a one-to-one mapping of source bytes for exact byte offsets;
- `ocr` is text recognized from an image by Tesseract;
- `structured` is document or archive content extracted by Kreuzberg.

If ten applicable rules request `text`, the network file is not downloaded ten
times: its bytes and extracted representation are shared by all those actions.
Without `--download`, no persistent copy is saved in `loot`; temporary reading
is still required because otherwise `scan` could not run.

#### `inspect`: validate structure and meaning, not merely a string match

`inspect` is used when a regular expression is insufficient or would create a
dangerous amount of noise. It receives the source bytes and invokes one of the
built-in bounded inspectors. An inspector understands the particular format's
structure and creates a finding together with ownership and semantic context.

Examples:

- `private-key-material` parses PEM, OpenSSH, DER, and PKCS#12 and distinguishes
  actual private-key material from a public certificate. A `BEGIN CERTIFICATE`
  line is therefore not reported as a private key;
- `kubernetes-secret-json` checks the Kubernetes resource kind, `data` and
  `stringData`, Base64, and ownership by a particular object. It does not join
  a password from one object with a name from an adjacent `ConfigMap`;
- `group-policy-preference-password` parses GPP XML and locally decrypts
  `cpassword` without contacting a domain controller to validate the result;
- the AD LDIF/JSON export and Russian JSON/legacy-encoding inspectors preserve
  ownership of a value by its particular attribute or field.

The inspector allowlist is fixed and validated before scanning. It currently
contains `private-key-material`, `kubernetes-secret-json`,
`group-policy-preference-password`, `active-directory-ldif-secrets`,
`active-directory-json-secrets`, `russian-json-credential-value`, and
`russian-legacy-credential-value`. A rule cannot supply a program name,
command, URL, or arbitrary Python module, so `inspect` cannot become a code
execution facility or a network validator for discovered data.

A single rule may combine actions. For example, on a `.pfx` file, `report`
retains the existence of the container while `inspect` separately attempts to
confirm private-key material. If the container is corrupt or protected by an
unknown password, the metadata finding remains even when no semantic finding
can be produced. An actual inspector failure is recorded separately. When
inspection succeeds, both findings remain: “a potentially important container
was discovered” and “private-key material was confirmed in the container.”
Rules apply to files; the `directory` and `path` fields describe a file's
location, but `report` neither copies nor reports the directory object itself.

## 3. Content analysis and file integrity

| What changed | Brief explanation | Benefit | Example or important clarification |
| --- | --- | --- | --- |
| Each match is now a separate persisted finding | The original version already used `finditer`, but primarily stored match counts and displayed no more than five matching lines of 500 bytes each. All values, match boundaries, context, and provenance are now retained. | Complete evidence is not lost in abbreviated console output and survives resume. | The improvement is in preserving results, not in introducing enumeration of all regex matches. |
| Extraction is split into independent representations | Text, printable strings, raw data, OCR, and structured data have explicit semantics and their own errors. | A rule identifies the representation in which a secret was found; strings from a binary file are not presented as an extracted document. | The `raw` representation preserves a one-to-one byte-to-text mapping for exact offsets. |
| Known structured formats no longer hide parser failures | For DOC/DOCX/PDF/XLS/XLSX/PPT/EML and other known containers, extractor failure no longer silently becomes a “successful strings search.” | A corrupt or unsupported document produces a visible error rather than a false absence of findings. | A file's error remains local, and scanning continues. |
| OCR is now an explicit local stage | Tesseract runs with a fixed argument list, without a shell, with a timeout and an explicit error when the executable or language data is missing. | Image processing is predictable and prevents command injection through filenames or findings. | OCR already existed in the original version; strict representation selection and error handling are new. |
| Added bounded re-reading of changing files | If identifying metadata changes, EOF occurs early, or reading makes no progress, the file is reopened for a full read: the initial attempt plus no more than three retries. Parts of different attempts are not combined. | A detected change triggers a bounded full re-read, and lack of progress cannot cause an infinite read loop. | This is not an atomic server-side snapshot: once retries are exhausted, the last complete stream, even if it changed during reading, may be accepted with `changed`; without a complete stream, the object receives `error`. |
| Added post-read metadata verification | The object manifest stores size, metadata change time, and the SMB file identifier when available; after reading, the object is checked for changes. | A stable file is read once, while a changed file is processed again in a controlled manner. | Accepted post-read metadata does not trigger an immediate retry; a later change is detected on the next visit to the object, for example through `--refresh-resume`. |
| Buffer bytes are reused within the new pipeline | A retrieved memory- or disk-backed buffer is passed to the parser and the safe file-copy writer without requiring another temporary file. | The file is still retrieved from the network once, with fewer local temporary-file operations. | Saving byte-for-byte copies without a second SMB download was already supported upstream; what changed is the local data handoff and how it is verified. |
| Required analysis failures are now object errors | An unreadable selected file or a missing required extractor is no longer treated as a successful check. | The final status reflects incomplete analysis instead of hiding it. | The run will normally receive `complete_with_errors`, but other objects will still be processed. |
| Local and SMB objects use consistent accounting and analysis rules | Local scans retain the same statuses, findings, provenance, retries, and progress where applicable. | Results from local rechecking of saved copies are comparable to network scans. | Local scanning already existed in the original version; its reliability and output have been unified. |
| Values and context are not masked | SQLite and optional JSON retain complete original values and context. The console and text log show the complete unmasked matched value with a short surrounding-context preview, typically up to 60 characters on either side; inspector semantic-context previews are limited to 120 characters. | Complete evidence is preserved while text output remains readable. | `--quiet` omits the surrounding context, not the path, value, or stored context. Context appears alongside the finding, not as an additional context line. Local results must be treated as sensitive. |

## 4. Persistent state, resume, and resilience

| What changed | Brief explanation | Benefit | Example or important clarification |
| --- | --- | --- | --- |
| Added a SQLite scan journal | Identity information, status, reason, attempt count, findings, exclusions, counters, and checkpoints are stored for each server, share, directory, and file. | After a failure, it is clear what was actually completed, skipped, or left unprocessed. | The current database schema version is 9; file content-analysis outcomes are recorded separately. |
| Transaction integrity is preserved across failures | Object status, findings, and the checkpoint are committed atomically with `synchronous=FULL`; output is produced only after the transaction commits. | A crash does not leave an object in `processed` without its corresponding findings, or a finding without the object's result. | An unfinished batch of operations can safely be repeated. |
| Introduced explicit object statuses | The main values are `processed`, `skipped`, and `error`; `changed` is stored as an additional flag. | The summary distinguishes “not selected by processing policy” from “attempted but failed.” | Excluded objects are accounted for separately from these statuses. |
| Introduced explicit run statuses | The values are `running`, `complete`, `complete_with_errors`, `interrupted`, and `preflight_failed`. | The status of the entire run is not confused with an individual file error. | A run cannot become `complete` while `pending` or `in_progress` objects remain. |
| Local errors no longer terminate the entire scan | A server, share, directory, file, rule, or representation error is recorded, and the rest of the scan scope is processed. | A single `ACCESS_DENIED` does not prevent results from all other shares. | SMB `ACCESS_DENIED` on a specific resource remains a visible object error but yields terminal `complete` by itself; other object errors yield `complete_with_errors`. |
| System errors leave a resumable run | SQLite failure, a worker crash, or an inability to continue reliably stops processing without falsely reporting success. | A broken accounting mechanism is not hidden by continuing with unreliable results. | The transaction is rolled back, and the saved state can be inspected and used to resume. |
| Added distinct exit codes | `0` means `complete`, `2` means completion with status-affecting object errors, `3` means credentials were rejected, `4` means preflight was unavailable, and `5` means a state or system error; a signal interruption preserves `interrupted` state. | Automation can distinguish the quality of a completed result from authentication, network, or state problems. | SMB `ACCESS_DENIED` errors stay visible in reports but do not change exit code 0 to 2 on their own. |
| State is created automatically | A new scan receives a unique SQLite database under `${XDG_STATE_HOME:-~/.local/state}/manspider/scans`; the directory can be overridden with `MANSPIDER_STATE_DIR`. | Users no longer need to choose a `--state-file` for every run. | Explicit `--state-file` and `--resume` remain available for automation scripts. |
| Added interactive resume selection | On the next launch in an interactive terminal, unfinished scans not held by another process are displayed newest first; users can choose a number or start a new scan. Completed-with-errors sessions containing proven network failures are also offered. | After a power or VPN outage, the required session can be found without manually searching for files. | Successfully completed, corrupt, and locked state databases are not offered. |
| Non-interactive launches do not require a resume-choice prompt | Without an interactive terminal, new state is selected automatically unless resume was explicitly requested; `--no-resume-prompt` disables the resume chooser in an interactive terminal as well. Main-scan approval is a separate requirement. | Scripts can explicitly choose new state or a saved session without waiting for an interactive selection. | Automated resume uses `--resume FILE --yes`; `--no-resume-prompt` does not grant approval. Without `--yes`, a non-interactive invocation cannot start the main scan. |
| Added a state-database lock for the duration of a run | A sidecar lock file prevents two processes from using the same SQLite database concurrently; the OS releases the lock after a crash. | Conflicting object claims and duplicate work within a run are prevented. | The second process exits with code 5 before the main scan. |
| Resume checks a fingerprint of the search conditions | Servers, scope, filters, rules, and processing policy must match; execution settings such as worker count, verbosity, and the JSON path may change. | Old results are not mixed with results obtained under different search conditions. | Changing the rule pack or `--allow-external-dfs` requires a new scan; the number of workers may change. |
| Added stable object and finding identifiers | Completing the same object again does not create a duplicate finding. | Resume and retries do not inflate results. | Identical secrets in different network locations still remain separate findings. |
| Default resume processes only unfinished work | `pending` and `in_progress` objects, objects eligible for retry, and only the necessary ancestor servers, shares, and directories are reopened. Completed neighboring subtrees are not enumerated. | Continuing after a brief failure does not turn into a full repeat traversal. | A single unfinished, deeply nested file requires traversing its ancestor chain, but not 523 neighboring directories. |
| Added resume with a tree refresh | `--refresh-resume` and `--rescan` re-enumerate the entire tree to find new or changed objects, but do not read the contents of unchanged files with a terminal result. | Users explicitly choose between fast continuation and bringing an earlier scan up to date. | Fast resume may not see a new file in an already completed neighboring subtree; a tree refresh will. |
| Fixed the local-directory checkpoint | A local parent is completed only after traversing its entire subtree, not immediately after its own files. | An interruption between subdirectories cannot hide undiscovered files from the next resume. | Ctrl+C after the first of three subdirectories leaves its parent unfinished; resume discovers the other two without rereading completed files. |
| Retry rules are now explicit | Processing an `in_progress` object restarts after a crash; ordinary errors are bounded by `--object-retries`. Proven network errors get a fresh visit on each resumed invocation without resetting history. Unchanged `skipped` objects are not reconsidered under the same processing policy. | Repeated outages do not permanently exhaust resume eligibility; there is no infinite same-invocation retry loop. | A changing file has a `1 + 3` read budget; a network failure permits one additional full read, at most five with mixed causes. |
| Added file-read recovery after network disconnects | The partial buffer is discarded and one retry reads from the beginning. Reconnect pauses for the same endpoint within a worker grow from 1 to 30 seconds. | Brief disconnects leave fewer files unanalyzed, while failed reconnects are paced. | No extra health probes or concurrency; failed reads can add retry traffic. This is not a cross-process request-rate limiter or an indefinite VPN wait. |
| Added migrations for older state databases | The scanner transactionally upgrades schemas 2–8 to schema 9, retaining findings and coverage observations; retired schema-6 review marks are discarded. Analysis outcomes missing before schema 8 remain `unknown`. | Existing databases are retained without inventing missing analysis history. | Migration does not read source files. The web viewer separately reads schemas 7/8/9 without migration; upgrading 8 → 9 does not rewrite historical contexts or finding IDs. |
| Strengthened shutdown on signals and worker crashes | SIGINT, SIGTERM, SIGHUP, and KeyboardInterrupt trigger worker shutdown, temporary-resource cleanup, and preservation of `interrupted` state; crash scenarios verify committed-data integrity and resume. | A handled interruption does not leave a false terminal status, and the database remains recoverable after a crash. | SIGKILL of an individual supervisor cannot technically guarantee cleanup of every descendant; unfinished objects are processed again on resume. |
| Cancellation survives a dependency destructor | The Ctrl+C request is retained separately from its exception and checked before new work; repeated Ctrl+C cannot interrupt cleanup. | A worker does not continue scanning merely because Python suppressed an exception inside `__del__`. | If the first Ctrl+C interrupts disposal of a cryptographic object, the next work checkpoint still cancels the scan. |
| Final output waits for owned workers to stop | On Linux, the coordinator creates a private process session; shutdown checks membership and includes surviving or orphaned descendants. | Workers cannot add findings after the final summary, and neighboring terminal commands are not signalled. | The supervisor stops a surviving worker after its coordinator crashes; stuck processes receive bounded, progressively stronger shutdown signals. |
| Fixed recovery after SMB negotiation disconnects | `No answer!` is classified as a network error only when its origin in installed Impacket is proven; the failed constructor's socket is released without SMB commands. | Two consecutive outages do not prevent the next resume from retrying the file after connectivity returns. | Old errors already saved without a network marker are not reclassified from text; start a new scan if their ordinary retries are exhausted. |
| Temporary storage is isolated per run | A temporary directory is created only when needed at the start of a particular scan and removed after normal completion or interruption. | Multiple runs no longer share the former global `/tmp/.manspider`, and temporary copies do not accumulate during normal operation. | A named temporary file is created only where the extractor actually requires a filesystem path. |

## 5. Performance and resource use

| What changed | Brief explanation | Benefit | Example or important clarification |
| --- | --- | --- | --- |
| Scheduling moved from servers to shares | Persistent workers receive independent `(target, share)` tasks instead of one sequential process for an entire server. | Multiple large shares on one server can use the available global concurrency budget. | With `--threads 5`, work is no longer limited to two active processes merely because there are two servers. |
| Added safe splitting of a large share | When there are few shares, already assigned top-level subtrees are split without assigning a subtree to multiple workers. | One large share no longer leaves the other processor cores and workers idle. | Each subtree belongs to only one worker. |
| Added a per-server session limit | `--threads` remains the global limit, while the new `--max-sessions-per-host` defaults to 4. Each I/O worker has its own SMB session. | Concurrency is bounded both globally and per endpoint; a single Impacket connection is not used concurrently. | The limit is keyed by the normalized endpoint string: different DNS or IP aliases of one physical server are not automatically merged. The value can be changed explicitly. |
| SMB sessions and share connections are reused | A worker retains its connection, and the SMB2/3 share connection stays open while the share is processed and is guaranteed to close in `finally`. | Hundreds of thousands of unnecessary `TREE_CONNECT` and `TREE_DISCONNECT` exchanges are eliminated on a large file corpus. | After reconnecting, the share is reopened on the new connection. |
| Added a bounded retrieval and extraction pipeline | SMB enumeration and reads run alongside local extraction through a queue of no more than eight files; a full queue applies backpressure to retrieval. | The network and parser spend less time idle, while memory and temporary storage do not grow without bounds. | The original version already created a separate analysis process per file; the new design uses a persistent bounded pipeline and shuts down the FIFO queue correctly. |
| Added a memory-backed buffer | Retrieved data stays in RAM up to 8 MiB, then automatically spills to disk without truncation. A named temporary file is created only for an extractor that actually requires a filesystem path. | Mandatory temporary-file writes, re-reads, and deletions are removed for each remote object. | 8 MiB is the memory threshold, not `--max-filesize`; the default maximum remote file size remains 10 MiB. |
| Structured extraction processes file batches with count and total-size limits | Validated formats with known MIME types are processed through the Kreuzberg bytes API in batches of up to eight files and 16 MiB; a batch failure falls back to the single-file bytes API, while the path API remains for formats and calls that require it. | Processing startup and filesystem overhead are reduced without changing extraction results. | Automated tests compare text obtained through the path API and the bytes API on the same file corpus. |
| Optimized post-read metadata verification | SMB2/3 obtains size and metadata change time in the already required `CLOSE` response; SMB1 performs `query_file_info` without write access on the open file. Directory re-enumeration is used when reliable post-read information is unavailable. | Repeated directory listings are reduced without giving up change detection. | After reconnecting, or for an unsupported or ambiguous result, a conservative fallback is always used. |
| Processing results are written to SQLite in batches | Individual workers batch object claims and result writes, while SQLite serializes transactions on the shared database; the default number of results written in one batch has increased to 64. | Fewer disk synchronizations and less database write contention, with `synchronous=FULL` retained. | There is no separate centralized writer process; findings, status, and checkpoint remain in one atomic transaction before output. |
| Added conservative regex prechecks | Only necessary match conditions are derived from the actual expression and its flags; if they are absent from the text, the expensive regex is not run. Unknown syntax uses the original execution path. | Local CPU load is reduced without missing valid matches. | The optimization is derived from the regex itself, not the rule name. |
| Added bounded metadata rule-routing caches | Invariant metadata groups and prepared conditions are cached using all fields that affect the result, with a cache memory limit. | Large rule packs are cheaper to apply to hundreds of thousands of object-manifest entries. | Selected rule identifiers are checked for exact agreement with direct evaluation. |
| Reduced auxiliary local I/O and SQL operations | Counter and checkpoint updates are coalesced, and unnecessary `mkdir`, `stat`, and `unlink` calls are removed for memory-backed objects. | Less CPU and disk load on the scanner host without additional SMB reads. | CPU time fell by 23–42% on the tested local parsing corpora; total scan time in a separate paired SMB comparison remained within measurement uncertainty. |
| Added exact comparison of run results | Comparison covers not just counts but the full multiset: path, rule, representation, value, context, offset, classification, provenance, statuses, exclusions, and errors. | A speedup cannot be accepted if it changes the evidence or scan scope. | Comparison was used after scheduler, pipeline, DFS, and crash-resume changes. |
| Verified a full-scan speedup on a large file corpus | With the same file corpus and the same normalized rule pack, one warm-cache baseline run of `21:20.76` was compared with the median of three optimized runs of `6:52.38`; the final verification after DFS and session-lock changes took `7:06.77`. | This testbed achieved an approximately threefold speedup with the same 165 554 findings under exact comparison. | This does not promise the same factor on every network; after expanding to rule pack 2.7, the full benchmark on 201 674 files was not repeated. |

## 6. Output, scan progress, and diagnostic reports

| What changed | Brief explanation | Benefit | Example or important clarification |
| --- | --- | --- | --- |
| Text logs are separated by invocation | Each invocation, including a resume, creates a new log beside the session database; its name contains a timestamp and a random identifier. The full path is shown before scan approval. | Concurrent scans and separate resumes no longer mix their messages in one daily file. | For `scan.sqlite3`: `scan.run_20260914_130000_123456_a1b2c3d4.log`. Previous logs are not appended to, moved, or deleted. |
| Findings are emitted after a durable commit | Findings appear in real time only after a successful SQLite transaction: text output includes the full path and matched value, classification, rule, and a short context preview; SQLite and optional JSON retain the complete original context and provenance. | A finding shown to the user is already in the state database and will not be lost in the next crash. | Console line order may vary with concurrency, but the result set remains the same. |
| Human-readable output preserves complete matched values | The console and normal text log show the complete unmasked matched value, typically with up to 60 context characters on either side; inspector semantic-context previews are limited to 120 characters. Full original context remains in SQLite and optional JSON. Internal UUIDs, hashes, and cache keys are omitted. | Long matched values are not cut to the old 500-byte preview, while surrounding text and internal identifiers do not overwhelm the output. | `--quiet` omits surrounding context, not the value or path; context is not printed as an extra line. Scripts that parsed the previous counter and match lines need adaptation. |
| Proven same-line findings are grouped only in the console | Hits proven to belong to the same line in the same representation share one console entry. The highest-severity rule is displayed, with confidence breaking ties and stable ordering thereafter; the count and names of other unique matching rules appear in parentheses. | Specialists do not have to review the same source line repeatedly; the text log, SQLite, and optional JSON retain every separate finding. | Example: `rule="high-rule" ... (ещё 2 правила: generic-rule, token-rule)` (two other rules). Different lines or representations, and ambiguous coordinates, remain separate. |
| Findings JSON is created only on explicit request | `--json` writes beside the state database, while `--json-file` writes to the specified path; data is built from persisted state and includes progress, errors, and exclusions. | Convenient console and log output remains the default, with machine-readable results created only on request. | Coverage JSONL and SMB metrics are separate sidecars, not findings JSON. |
| Added detailed scan progress | Progress displays servers, dynamically discovered shares, directories and files, the values `processed`, `skipped`, `error`, and `changed`, findings, exclusions, and run status. | Users can see that the scan is advancing and how complete the result is. | Exclusions are not mixed with `skipped` status. |
| Added a dynamic remaining-time estimate | Every five seconds, a local estimator uses the existing object manifest and completion rate; after 10 seconds it displays remaining and total time, a range, and confidence. | Duration can be estimated without a full preliminary inventory. | For example: `elapsed=03:25; remaining~03:30 (02:27-05:15); confidence=medium`; `--no-eta` disables only the estimate. |
| Time estimates account for resume and an expanding scope | Each invocation establishes a new rate baseline; the early estimate has a wide range and can increase after a large subtree is discovered. | Previously completed objects do not create a falsely inflated processing rate. | In the measured full run, the median absolute error of the total-duration estimate was 2.48%. |
| Added passive SMB metrics | Existing connection, enumeration, read, and DFS operations contribute aggregate counts, byte volumes, errors, approximate p50/p95/p99, session counts, and reconnects to `*.smb-metrics.json`. | Degradation is visible from the client side without additional probes or load. | Percentiles are histogram bucket upper bounds. Credentials, content, and scanned-file paths are not recorded; the state-database path is present. `--no-smb-metrics` disables the report. |
| Added warnings for sustained degradation | A warning appears only after two consecutive observation windows; authentication and access failures are not treated as load signals. Concurrency does not change automatically. | A single timeout or permission denial does not cause a false alarm or unpredictable throttling. | These are client-observed latencies and errors, not reliable measurements of server CPU or RAM load. |
| Added a rule-coverage gap report | `*.unclassified-files.jsonl` contains accessible files with no extension, an unknown extension, no matching rule, or analysis disabled by a size limit or format policy; it uses metadata already obtained during enumeration. | After a real scan, recognized extensions and rules can be expanded based on the unknown names actually encountered. | The report does not open files or issue additional SMB requests; `--no-unclassified-report` disables it. |
| Coverage-report data is stored consistently across failures | Schema 8 retains the compact hybrid layout from schema 6, stores observations with the object's terminal-result update, and atomically rebuilds JSONL; fast resume does not duplicate rows. | A crash does not destroy the accumulated data used to improve rules. | Files in an excluded, inaccessible, or unlisted subtree are unknown to the scanner and cannot appear in the report. |
| Added a compact final summary | A final line is produced for `complete`, `complete_with_errors`, `preflight_failed`, and `interrupted`. | The outcome is immediately visible even after partially successful or interrupted work. | Detailed reasons remain in the state database and log. |
| Standardized local result permissions | Logs, copies, JSON, and sidecars use `0664`, directories use `0755`, and the state directory/SQLite use `0700`/`0600`. Finding values remain unmasked. | Results remain group-readable while the group cannot replace path components. | The data contains plaintext secrets, so the scanner host must be protected. |

## 7. Safe SMB reads, DFS, cold storage, and saving matching files

| What changed | Brief explanation | Benefit | Example or important clarification |
| --- | --- | --- | --- |
| Recursive authentication retries and duplicate reconnects were removed | The login routine does not retry a rejected identity; a transport failure permits one retry. Error formatting no longer reconnects; share enumeration permits one connection rebuild. | An error or expired password cannot cause an unbounded login loop and unnecessary server load. | Normal Guest/anonymous fallback remains. No default scan-wide failed-logon limit was introduced. |
| A read-only safety violation stops the scan | `ReadOnlySMBViolation` is preserved across reads, DFS, connection cleanup, and worker error delivery; the affected transport is discarded without further SMB requests. | A safety failure cannot become an ordinary file skip followed by a fallback attempt. | Exit code `8`, state `interrupted`; committed findings are retained. Ordinary access denial does not trigger this stop. |
| The share-enumeration service pipe is explicitly closed | The owned `IPC$\srvsvc` handle permits only the fixed interface binding and `NetrShareEnum`; its handle and owned tree reference are then released. | A service handle cannot remain open merely because the session or another `IPC$` reference is retained. | The additional CLOSE request concerns only the service pipe, not scanned file contents. |
| Directory enumeration cleans up after ordinary failures | Read-only open parameters are pinned; an ordinary listing or CLOSE error does not prevent release of the owned tree reference. A session with failed cleanup is retired. | A failed CLOSE cannot leave an uncertain handle available for subsequent work. | The primary error is preserved; after a safety violation, socket closure replaces protocol cleanup. |
| SMB file opens now use an explicit set of read-only permissions | SMB2/3 requests exactly `FILE_READ_DATA` access with the `FILE_OPEN` disposition; SMB1 additionally requests only read access to metadata and security-descriptor information. | The scanner explicitly requests no rights to create, overwrite, delete, or modify access control lists. | The original version also contained no intentional SMB writes; what is new is the explicit protocol flags and a verifiable guarantee. |
| Reads no longer unnecessarily block other clients | The share-access mask includes `FILE_SHARE_READ`, `FILE_SHARE_WRITE`, and `FILE_SHARE_DELETE`. | A file handle opened by MANSPIDER should not unnecessarily prevent an application from reading, updating, renaming, or deleting the file. | These flags do not grant MANSPIDER write access—they allow the corresponding operations through other open handles. |
| SMB1 file retrieval was rewritten as an explicit read loop | The safety-critical path no longer depends on the high-level `getFile`; it uses `CreateFlags=0` and requests no exclusive or batch opportunistic lock. | SMB1 behavior is now verifiable and consistent with the SMB2/3 read-only policy. | Early EOF and zero progress share the overall `1 + 3` attempt limit. |
| A source-level allowlist of SMB calls was added | Allowed operations include session setup and authentication, share and path enumeration, metadata and content reads, and a DFS referral query without modification rights. An unexpected direct Impacket call causes a test failure. | The regression suite detects accidental additions of data-modification APIs. | Separate before-and-after checks compare file contents, sizes, timestamps, and attributes on the server. |
| Full same-server DFS support was added for SMB2/3 | The implementation uses `FSCTL_DFS_GET_REFERRALS`, parses referral records of versions 1–4, reuses the original session, and preserves the namespace path in findings and state. | The DFS namespace is scanned without losing the original, understandable UNC path or creating an extra session. | Referral routing accounts for `PathConsumed` and the record lifetime; DFS referral transport over SMB1 is not supported. |
| External DFS referrals are disabled by default | A referral to another server is reported with a warning and skipped before DNS resolution, connection, or authentication; it is enabled only through `--allow-external-dfs`. | The scanner does not automatically leave the specified scope for an unexpected storage server. | Enabling the option uses the original scan credentials; work can extend beyond the servers specified on the command line, so the option is included in the resume fingerprint. |
| Cold-storage warnings were added | For `OFFLINE`, `RECALL_ON_OPEN`, and `RECALL_ON_DATA_ACCESS`, the full UNC path, non-default port, and flags are printed before reading or enumeration. Reading remains the default behavior. | The user can see in advance which object may trigger recall from HSM or cloud storage. | A warning cannot be issued in advance for a share root if its attributes become known only after the first enumeration. |
| Saved copies preserve the network hierarchy | Instead of a flat ASCII name, the path is `<loot>/target/share/path/filename`; a non-default port is included in the server-name component. | Files with identical names or contents from different locations do not overwrite one another, and the path remains understandable. | For example, `loot/server_port-1445/share/team/secret.txt`. |
| Byte-for-byte preservation is enforced by the new writer and tests | Already downloaded bytes are copied without converting text or archives, and the result is checked by hash and before-and-after state comparison. | The saved copy matches the bytes received from the server when using the new buffer and safe write path. | Byte-for-byte saving without a second SMB download was already a property of the original version; the hierarchy, writer, and strict verification are new. |
| Local writes of saved copies are protected against path attacks | The root directory is normalized before workers start; directory and file operations use no-follow directory descriptors, a new temporary file, and atomic replacement of the final file. `..`, a symbolic or hard link, a special file, or substitution of the final path do not redirect writes to a pre-existing file outside the pinned root. | A malicious SMB filename cannot make the normal writer overwrite an arbitrary local file on the scanner host. | A trusted local storage root is assumed: this is not isolation from an owner or superuser who moves the root itself or its ancestors. Saving fails if safe APIs are unavailable. |
| Rules and inspectors do not validate findings over the network | Discovered passwords, access tokens, and keys go only into findings, state, and configured output. They are not passed to SMB login, HTTP APIs, LDAP, Kubernetes, or a command shell. | Searching does not turn into automatic use of credentials or outbound leakage. | Discovered credentials are not used to log in; authentication uses the supplied identity and the normal fallback to a guest or anonymous session. |
| Every scanner-controlled writable path is proven local | State, SQLite sidecars, locks, logs, loot, reports, session slots, and temp are rejected on UNC, network or unknown filesystems, symlinks, untrusted owners, writable non-sticky ancestors, or ACL write masks. | A configuration or filename error cannot redirect a local artifact to customer storage. | Creation, replacement, and cleanup use pinned no-follow descriptors; regular-file stdout/stderr are checked too. |
| Third-party extraction is locally isolated | Exact `kreuzberg==4.10.2` is loaded lazily only from a proven-local installation and inside private temp/cache storage; caching is disabled and remote files are supplied as bytes or anonymous local snapshots. The complete temp locality proof runs once per process; later uses pin the directory by device/inode, and nested calls reuse the verified environment. | PDFium, Tesseract, and path-only extractors receive no UNC path or use a network HOME/TMPDIR; mount policy is not re-read for every document. | Later entries use `O_NOFOLLOW` and verify the original identity, owner, and private mode; MANSPIDER code and dependencies must be installed on local or read-only storage. |
| Unavoidable server-side effects of reading are documented | MANSPIDER requests no changes to scanned filesystem objects, but the server may create audit or logon events, update last-access time, or recall content from cold storage. | The read-only guarantee is stated honestly and can be checked at the level of scanner requests. | Read-only `NetrShareEnum` sends RPC request bytes through the existing `IPC$\srvsvc`, but does not write to a scanned file or change the share. Reading cannot be guaranteed to have literally zero effects. |
| The external guarantee boundary is explicit | A pre-start shell redirect, downstream pipe process, first CPython `__pycache__`, same-UID/root process, substituted dependency, and malicious server cannot be isolated by one Python process. | Operators know where OS and server controls are additionally required. | Strict operation uses Docker/helper, a local install, `PYTHONDONTWRITEBYTECODE=1`, server-side read-only ACL/snapshot, and a sandbox. |

## 8. Packaging, containers, tests, and operational verification

| What changed | Brief explanation | Benefit | Example or important clarification |
| --- | --- | --- | --- |
| A direct dependency on `cryptography>=45` was added | It is used by structural inspectors for private keys, PKCS#12, and GPP. | Key-material inspection relies on a dedicated library rather than regular expressions alone. | The other main dependencies from the original version are retained. |
| The SMB dependency is pinned | Runtime dependencies require exactly `impacket==0.13.1`; upgrading the protocol library requires renewed checks of protocol requests, compatibility, and read-only safeguards. | An installation cannot silently substitute unverified SMB behavior from a different dependency version. | Pinning does not replace transport safeguards; content extraction separately pins `kreuzberg==4.10.2`. |
| pytest test discovery was fixed | `testpaths = ["tests"]` prevents pytest from treating data fixtures as Python modules. | Test discovery stays focused on the intended test modules. | In the original baseline, automatic test discovery failed on a UTF-16 test file. |
| The test suite grew from two modules to 136 | As of 2026-09-19, `tests/` contains 136 `test_*.py` modules covering unit, integration, crash, browser, and protocol checks of accuracy, resume, read-only behavior, and performance. | Regressions are checked at the behavioral level, not merely through imports and a few formats. | The latest recorded full regression contained 8 147 checks: 8 146 passed, with one initial browser-test failure. After correcting test synchronization, three targeted reruns passed; this is not a claim of one completely green full run. Test sources are available in [tests/](tests/). |
| A reproducible Windows/SMB test corpus was added | A corpus of 200 920 files, 116 508 directories, and 1 024 shares was prepared for verification, including hidden and inaccessible paths and rule examples. | Scalability, performance, and accuracy checks can be repeated instead of estimating speed from an arbitrary folder. | The corpus, external fixtures, and lab-management utilities are not part of the public distribution. Test implementations are available in [tests/](tests/); some require separately retained local fixtures. |
| A reference comparison tool was added | Multiple SQLite state databases are compared by objects, findings, exclusions, and run status, with an optional integrity check. | Optimizations, work partitioning, and resume are checked for exact result equivalence. | Implemented in `man_spider/differential.py`. |
| The SMB compatibility matrix was expanded | Tested cases include real connections over SMB1 and SMB 2.0.2–3.1.1, signing, SMB3 encryption, Samba, DFS-marked roots, same-server and external referrals, and error-handling scenarios. | Share-connection, read, and session optimizations are not tied to a single Windows protocol version. | External DFS traversal was tested only with explicit opt-in. |
| Read-only state checks were added | Bytes and hashes, sizes, timestamps, modes or attributes, and expected access errors are compared before and after scanning. | Compliance with read-only behavior is confirmed by observing the test environment during execution. | The separate caveat about server-generated audit events, access times, and file recall from HSM storage still applies. |
| The Docker helper script was improved | `manspider.sh` keeps writable HOME/loot/log/state in a verified Docker local volume, uses UID/GID, TTY, `--rm`, and `MANSPIDER_IMAGE`, and rejects option-backed volumes. | Starting the helper from a mounted customer share creates no directories there before Python guards run. | The default volume is `manspider-runtime-<uid>`; Kerberos files are mounted separately and read-only. |
| Docker builds were made non-interactive | Installation of apt dependencies uses `DEBIAN_FRONTEND=noninteractive`. | Automated image builds do not hang on Kerberos or timezone configuration prompts. | The core system package set is not presented as new. |
| Kerberos files are mounted more safely in Docker | The file-based credential cache and the configuration file specified by `KRB5_CONFIG`, if provided, are validated and mounted read-only when running with Kerberos; unsupported cache types are rejected. | The container uses the host's Kerberos setup without writing to the cache or configuration. | Both a plain path and the `FILE:` prefix are supported. |
| One-command installation of the scanner and web viewer from source was added | On Linux, `bash install.sh` uses uv to install for the current user with Python 3.12 and the dependencies locked in `uv.lock`, including the web viewer. No `sudo` is required. | Both `manspider` and `manspider-web` are available from any working directory without activating a virtual environment or retaining the source checkout. | Obtain the fork source first. If the installer updates `PATH`, open a new terminal or run the printed command. To update, rerun the installer from an updated checkout. |
| Distribution artifacts are verified | Verification includes Ruff, compilation, dependency locking and synchronization, `wheel` and `sdist` packages, clean installation, the `manspider` console command, the packaged rule set, and the absence of private lab credentials. | The source working tree cannot silently diverge from the installable package. | The `wheel` package contains the same 2.7.0 rule set and runtime modules. |

## What is intentionally not presented as new

The following capabilities were already present in the original version and are not
presented as standalone additions in the tables above:

- local scanning and targets specified as IP addresses, hostnames, CIDR ranges,
  target-list files, or `host:port`;
- filename, extension, content, and date filters, `--wordlist`, the
  `--or-logic` flag itself;
- password, NTLM hash, Kerberos, AES key, and fallback to a guest or
  anonymous session;
- selecting an explicitly specified hidden share; upstream also attempted shares
  absent from enumeration, whereas the current version excludes them when their
  disk-share type is unknown;
- Kreuzberg, OCR through Tesseract, extraction from Office documents, and
  printable strings from binary files;
- finding all regular-expression occurrences through `finditer` and reading the entire
  selected text file;
- overlapping file retrieval and processing through a separate process;
- defaults: five workers, maximum file size 10 MiB, exclusions `IPC$`,
  `PRINT$`, `C$`, `ADMIN$`, and no default value
  for `--max-failed-logons`;
- the Python and Impacket runtime, uv, pipx, Docker, and declared support for
  modern Python versions.

## Important distinctions that are easy to confuse

| Concepts | Correct interpretation |
| --- | --- |
| The built-in default rule set and default CLI behavior | The rule set is called the default pack, but it is enabled only through `--builtin-rules`; scanning does not start without filters or rules. |
| No downloaded copies and not reading a file | Permanent copies are not saved by default; saving them requires `--download`. Content is still read temporarily if required by `-c` or a rule; metadata-only searches do not transfer contents. SQLite and logging still preserve results, including found secrets in plaintext. |
| 8 MiB and 10 MiB | 8 MiB is the threshold for keeping the buffer in memory before spilling to disk; 10 MiB is the original default for `--max-filesize`. Increasing the buffer does not permit processing larger remote files. |
| Metadata coverage and content coverage | A filename or extension rule may identify an interesting file without reading its contents. This does not mean that secrets inside it have been checked. When saving copies is enabled, a metadata match may still cause the file to be downloaded solely for saving. |
| Fast resume and tree refresh | Fast resume completes the previous unfinished work; a tree refresh also searches for new and changed objects in already completed subtrees. |
| Read-only behavior and no effects whatsoever | There are no explicit requests to modify remote objects, but authentication, auditing, access-time updates, and HSM recall may be internal effects of reading itself. |
| Passive metrics and server monitoring | MANSPIDER observes client-side latency, data volumes, and errors, but without server access it cannot reliably determine CPU load, memory usage, disk queue depth, or overall load. |
| Speed improvements and server requests per second | Preserving total operations and bytes does not guarantee an unchanged short-term request rate. The default limits are considered reasonable, but they are not guaranteed to be harmless to every low-powered server. |
| Rules and the Internet | The rule engine and inspectors do not access the Internet. The scanner itself needs network access to the specified SMB servers, and Kerberos may require DNS and a KDC; external DFS requires explicit opt-in. |
| A local rule file and a network filesystem | MANSPIDER does not retrieve rules from Internet links, but a file specified through `--rules` or `--wordlist` on a UNC path or network mount is read through the normal filesystem API and may cause network access by the operating system itself. |
| Go experiments and the current implementation | `go-smb`, `pavao`, and rewriting in Go were investigated, but have not been integrated into the main implementation. |
| Installation URLs and this modification | README and project URLs in package metadata point to the `ShAmRoWw/MANSPIDER` fork, installed with its `install.sh`. Package metadata preserves the original author and adds ShAmRoWw. The package version remains `2.0.0`, and the helper's default fallback Docker image still belongs to `blacklanternsecurity`. Installing upstream does not provide these modifications; for Docker, build from the fork source and explicitly set `MANSPIDER_IMAGE`. |

## Implementation map and further details

### Local web viewer

| What changed | Brief explanation | Benefit |
| --- | --- | --- |
| Separate `manspider-web` command | A local interface reads existing SQLite sessions; it neither starts scans nor connects to SMB. Installed through the optional `web` dependencies. | Inspect findings during or after a scan without additional requests to customer servers. |
| Display filters and object cards | Filter file/finding properties, group by object, and expand values and context. Without explicitly selected filters, all findings are available, including weak `configuration-data-file` matches. | The specialist controls result filtering; weak findings are not hidden by default, and original results are preserved. |
| Manual finding-review marks | Each finding can be marked reviewed and unmarked. A filter shows all, only unreviewed, or only reviewed findings; nothing is hidden by default. Marks persist separately in `<session>.review`. | Specialists can remove already reviewed evidence from their working view without deleting findings, changing scan statistics, or contacting the server again. |
| Pagination and live updates | Bounded local database queries, cached summaries, and change notifications that do not move the current results. | Bounds memory use and avoids disrupting analysis of the current page. |
| Elapsed and remaining scan time are shown | The viewer displays elapsed time for the current main-scan invocation and an estimated remaining-time range with confidence. Preparation, approval waiting, and downtime between invocations are excluded; resume starts a new timing baseline. Stale, disabled, or unavailable estimates are explicitly identified. | Specialists can follow timing alongside live findings using only local scan state, without extra SMB probes. |
| Separate content-analysis accounting | Schema 8 distinguishes `analyzed`, `partial`, `not_analyzed` and `unknown` from completed selected checks, independently of findings and `processed`; observations use the existing transaction. | A check with no matches counts, while downloading a filename match does not count as analysis. For example, a completed raw-byte check plus failed OCR gives `partial`; bytes received before a read failure alone give `not_analyzed` with `analysis_read=true`. |
| Analysis outcomes in the interface and JSON | Cards, the object list, summaries and filters use the separate analysis state. JSON findings include `analysis_status`, `analysis_reason` and `analysis_read`; `progress.analysis_counts` counts files, including those without findings. | Shows actual execution of selected rules rather than presumed reads of every file. Legacy data remains unknown; resume retains confirmed outcomes for unchanged files. |
| Added RU/EN and three theme choices | Russian/English interface and system/light/dark themes; the browser stores preferences and explicitly saved filters, never finding records. | Comfortable presentation without rescanning; values, paths and rule identifiers remain unchanged. |
| Local viewing without login | Only `127.0.0.1`, without a token or cookies; Host/Origin checks, cross-site restrictions, local assets and safe text rendering remain. Other users and processes on this computer can read unmasked findings through HTTP. | The page opens immediately without authentication; the service is not published on network interfaces and does not execute found text. There is no authorization boundary between local users. |

See [README.md](README.md) for installation and viewer startup.

### Main files

| Area | Main files |
| --- | --- |
| Command line, validation, and effective configuration | [`man_spider/cli.py`](man_spider/cli.py) |
| Scan scope and filtering | [`man_spider/filters.py`](man_spider/filters.py) |
| Credential preflight | [`man_spider/preflight.py`](man_spider/preflight.py) |
| File analysis when scanning large networks | [`man_spider/policy.py`](man_spider/policy.py), [`man_spider/formats.py`](man_spider/formats.py) |
| Rule loading, validation, and examples | [`man_spider/rules.py`](man_spider/rules.py), [`tests/test_rules.py`](tests/test_rules.py) |
| Built-in rules | [`man_spider/builtin_rules_v3.json`](man_spider/builtin_rules_v3.json) |
| Parser and structural inspectors | [`man_spider/lib/parser/parser.py`](man_spider/lib/parser/parser.py), [`man_spider/lib/parser/`](man_spider/lib/parser/) |
| SQLite state and resume | [`man_spider/state.py`](man_spider/state.py) |
| Scheduler and processing pipeline | [`man_spider/lib/spider.py`](man_spider/lib/spider.py), [`man_spider/lib/spiderling.py`](man_spider/lib/spiderling.py) |
| Safe SMB reads and DFS handling | [`man_spider/lib/smb.py`](man_spider/lib/smb.py), [`man_spider/lib/file.py`](man_spider/lib/file.py) |
| Safe local saving of copies | [`man_spider/lib/localfs.py`](man_spider/lib/localfs.py) |
| Scan progress, time estimation, and telemetry | [`man_spider/progress.py`](man_spider/progress.py), [`man_spider/metrics.py`](man_spider/metrics.py) |
| JSON and coverage report | [`man_spider/output.py`](man_spider/output.py), [`man_spider/unclassified.py`](man_spider/unclassified.py) |
| Local web viewer | [`man_spider/web.py`](man_spider/web.py), [`man_spider/web_data.py`](man_spider/web_data.py), [`man_spider/web_static/`](man_spider/web_static/) |
| Exact result comparison | [`man_spider/differential.py`](man_spider/differential.py) |
| General user documentation | [`README.md`](README.md) |

## Additional result-accuracy and integrity fixes

| What changed | Brief explanation | Benefit | Example |
| --- | --- | --- | --- |
| Explicit content skips take precedence | `--skip-formats` is applied after `-e` overrides automatic format blocks. | Selecting an extension no longer cancels its content-analysis prohibition. | `-e txt --skip-formats txt` does not enable TXT analysis. |
| Directory-filter separators are consistent | `/` and `\` are canonicalized without changing substring semantics. Potentially incompatible older sessions require a new scan. | Required trees are not lost from includes or missed by exclusions. | `--exclude-dirnames finance/reports` excludes the corresponding subtree. |
| Explicit encoding errors remain visible | Malformed BOM-marked Unicode retains an incomplete-analysis diagnostic after fallback extraction; existing findings remain. | Empty or distorted fallback text is not reported as fully analyzed. | Truncated UTF-16 is marked `partial`, not `analyzed`. |
| JSON cannot replace session-support files | Early and publication-time checks protect the database, its journals, lease lock, and manual-review storage. | A report cannot overwrite that storage or invalidate the session lock. | `scan.sqlite3-wal` is rejected as a destination even during resume. |
| Identical context is reused in memory | Matches within one representation share an immutable string; the reuse cache has 4,096 entries at most, without truncating findings or context. | Dense matches need fewer transient copies without losing evidence. | Multiple rules on one line share its context object; repeated SQLite storage is additionally optimized in schema 9, while the JSON format is unchanged. |
| Ordinary messages escape untrusted fields | Paths and reasons are safely displayed for exclusions, HSM and errors as well; tracebacks retain deliberate multiline structure. | Filename controls cannot manipulate terminal output or forge log lines. | ESC is displayed as `\x1b`; the original SMB/database name is unchanged. |

Related checks: [filtering](tests/test_filters.py), [Unicode decoding](tests/test_text_unicode_decode.py),
[JSON/session paths](tests/test_json_session_paths.py), and [log-field safety](tests/test_log_field_safety.py).

## State and result-viewing boundary fixes

| What changed | Brief explanation | Benefit | Example |
| --- | --- | --- | --- |
| File finding pages validate their result-set version | Replaced findings or changed review-filter membership prompt a restart of that file's pages while keeping already displayed evidence visible. | A stale cursor cannot present an empty page as the end of the findings. | After retrying a file with 60 findings, restarting its pages exposes the remaining 10. The version marker is not an access key or authentication. |
| SQLite automatic rollback preserves the original cause | An already rolled-back transaction is not rolled back again. | A disk-full failure is not replaced by a misleading no-active-transaction error. | `database or disk is full` remains the StateError cause; resume is available after the underlying issue is resolved. |
| Custom rules receive additional early validation | Unpaired Unicode surrogates and JSON/regex-compiler limit failures become normal configuration errors before session creation. | These invalid rules do not leave empty sessions or escape as unhandled exceptions. | Cyrillic, emoji and supported exact large integers still work; interpreter limits are not increased. |

## Resilience with limited CPU and memory headroom

| What changed | Brief explanation | Benefit | Example or important caveat |
| --- | --- | --- | --- |
| Removed circular worker waiting | Once all jobs have been dequeued, waiting extra processes no longer need a free slot to exit; already claimed work finishes as before. | Scans finish even when coordinators occupy all global slots. | The previous hang on two Windows hosts with `-t 2` is resolved without raising concurrency limits. |
| Repeated context is stored once | Schema 9 stores an identical full context string once for findings belonging to one object, without merging findings or changing their IDs. | Smaller local databases and less writing for dense matches. | Tested 512 KiB line: all 97 findings retained, database 49.44 → 1.90 MiB. Historical rows are not compacted automatically; JSON still includes full context for each finding. |
| Timer updates do not recount the web summary | A transactional data revision distinguishes real changes from elapsed-time updates; review marks do not require recounting overall totals, and concurrent requests for one scan share the computation. | Less repeated SQLite and CPU work while the viewer is open. | 100 timer updates require one aggregate calculation when data is unchanged. An initial expensive query can still exceed the existing deadline. |

Related checks: [scheduler](tests/test_scheduler.py), [context storage](tests/test_state_local_efficiency.py),
and [web data layer](tests/test_web_data.py). Individual measurements do not guarantee the same performance on another host.

## Limits to the scope of this table

The table describes functionally significant differences and separately covers major
internal changes affecting accuracy, speed, recovery, or
safety. It does not enumerate every function rename, formatting change,
test fixture, or documentation line. The following are not implemented and are therefore
not included: removing the remaining `QUERY_INFO`, a persistent process pool
for servers, new scan-progress counters, streaming generation of the full JSON report, and a separate
request-rate limiter. Automatic telemetry-based throttling is not implemented.
Reconnect pauses after confirmed network failures do not regulate healthy scan speed.
