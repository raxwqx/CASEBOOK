<div align="center">

# 🔐 CASEBOOK

### Offline-First Digital Forensics & Incident Investigation Workspace

[![Tests](https://github.com/raxwqx/CASEBOOK/actions/workflows/tests.yml/badge.svg)](https://github.com/raxwqx/CASEBOOK/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-none-16A34A?style=flat-square)](#security-and-privacy)
[![License: MIT](https://img.shields.io/badge/License-MIT-64748b?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-64748b?style=flat-square)](#supported-environments)

**Preserve evidence. Record decisions. Verify integrity. Export a report.**

CASEBOOK is a local, terminal-based workspace for organizing digital investigation cases. It preserves original inputs, hashes evidence with SHA-256, validates ZIP imports, records analyst notes and findings, verifies a local hash-chained audit journal, and generates portable reports.

[English](#english) · [Türkçe](#turkce) · [Quick start](#quick-start) · [Command reference](#command-reference) · [Security model](#security-model-and-limitations)

</div>

---

<a id="english"></a>

# 🇬🇧 English

## Contents

- [What is CASEBOOK?](#what-is-casebook)
- [Who is it for?](#who-is-it-for)
- [Capabilities](#capabilities)
- [What CASEBOOK does not do](#what-casebook-does-not-do)
- [Quick start](#quick-start)
- [Installation](#installation)
- [Command reference](#command-reference)
- [End-to-end investigation example](#end-to-end-investigation-example)
- [Case directory layout](#case-directory-layout)
- [Evidence ZIP format](#evidence-zip-format)
- [Integrity verification explained](#integrity-verification-explained)
- [Reports](#reports)
- [Security model and limitations](#security-model)
- [Testing and development](#testing-and-development)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Roadmap and status](#roadmap-and-status)
- [Contributing, security reports and license](#contributing-security-reports-and-license)

## What is CASEBOOK?

CASEBOOK is an **offline-first case-management and evidence-integrity helper** for digital forensics and incident response (DFIR). It gives an investigation a consistent place to keep original files, derived files, acquisition context, analyst observations, findings, a timeline, an audit journal, and reports.

It is intended to sit **alongside** specialist tools. For example, an analyst may export JSON or text output from a network analyzer, log-review utility, or other approved tool, then preserve that export and document the interpretation in CASEBOOK. CASEBOOK organizes and verifies records; it does not replace the analysis engine that created an artifact.

### The workflow

```text
CREATE CASE
    ↓
IMPORT FILE OR ZIP BUNDLE
    ↓
PRESERVE ORIGINAL + CALCULATE SHA-256
    ↓
RECORD NOTES, EVENTS AND FINDINGS
    ↓
VERIFY FILES, INDEXES AND AUDIT CHAIN
    ↓
EXPORT HTML / MARKDOWN / JSON REPORT
```

## Who is it for?

- **Students and lab users** who need repeatable, synthetic investigation exercises.
- **Security analysts** who want a small local workspace for records and exported findings.
- **DFIR practitioners** who need to distinguish source artifacts from extracted/derived material and analyst interpretation.
- **Tool builders** who want to document the output of their own analyzers without having to build a case-management layer first.

Only handle evidence you are authorized to possess and process. Use synthetic data for demos and tests.

## Capabilities

| Capability | What it means in practice |
|---|---|
| Structured cases | A predictable folder layout separates case metadata, original evidence, derived evidence, findings, notes, audit events and reports. |
| Original preservation | Input files are copied into the case. CASEBOOK hashes the source and stored copy and refuses to register the evidence if the digests differ. |
| SHA-256 inventory | Evidence and accepted ZIP members are recorded with hashes and byte sizes. |
| Defensive ZIP import | Rejects unsafe paths, symbolic links/special entries, duplicate paths, encrypted members and archives exceeding configured resource limits. |
| Derived evidence | Accepted regular ZIP members are extracted under a separate derived-evidence location; the original archive is retained. |
| Append-oriented records | JSON and JSON Lines (`.jsonl`) keep records readable and easy to inspect. |
| Hash-chained audit journal | Each journal event includes a digest and a link to the preceding event; verification checks the sequence and links. |
| Investigation notes and timeline | Records analyst-authored notes with a type and UTC-normalized event time, then displays a chronologically sorted timeline. |
| Evidence-linked findings | Findings can include severity, status, description and references to evidence IDs already in the case. |
| Portable reports | Exports a standalone HTML report or Markdown/JSON report data. Existing report paths are not silently overwritten. |
| Local-first operation | No CASEBOOK network requests, telemetry, accounts, remote APIs, or third-party runtime dependencies. |
| Regression tests and CI configuration | Includes a standard-library `unittest` suite and a GitHub Actions matrix configured for supported Python versions on Linux, macOS and Windows. |

## What CASEBOOK does not do

CASEBOOK is deliberately scoped. It does **not**:

- acquire live memory, disk images, or volatile system state;
- parse PCAP/PCAPNG, inspect a live network, scan ports, or perform reconnaissance;
- log in to accounts, access mailboxes, decrypt data, or bypass controls;
- execute files imported as evidence;
- automatically classify an artifact as malicious or decide what happened;
- prove who created a file, when it was originally created, or whether its contents are factually true;
- digitally sign a case, provide a trusted timestamping service, encrypt the case directory, or guarantee legal admissibility.

Use dedicated tools for acquisition and technical analysis. Record the tool, source, version, method and relevant context as analyst notes where appropriate.

## Quick start

These commands assume CASEBOOK is installed and `casebook` is available on your `PATH`.

```bash
# 1. Create a case
casebook init CASE-001 --title "Training Lab" --analyst "analyst-handle"

# 2. Add the included synthetic demonstration bundle
casebook add CASE-001 examples/casebook-demo-bundle.zip \
  --source "CASEBOOK synthetic demo" \
  --note "Bundled training artifact; not real incident evidence"

# 3. Check recorded integrity
casebook verify CASE-001

# 4. Generate a standalone HTML report
casebook report CASE-001 --format html

# 5. Review case metadata and timeline
casebook show CASE-001
casebook timeline CASE-001
```

The HTML report is written into the case's `reports/` directory unless you provide `--out`. Keep the report and the case data protected: reports may disclose filenames, observations, findings and other sensitive details.

### First-run alternative: enter the case directory

```bash
casebook init CASE-001 --title "Training Lab"
cd CASE-001
casebook add . ../examples/casebook-demo-bundle.zip --source "synthetic demo"
casebook verify .
casebook report . --format html
```

In the second example, the relative path assumes `CASE-001/` and `examples/` are siblings under the project directory.

## Installation

### Requirements

- Python **3.10 or newer**.
- Linux, macOS or Windows with a compatible Python installation.
- No third-party **runtime** packages.
- For development, the project is installed in editable mode and tests use Python's built-in `unittest` framework. Building/installing from source may require standard Python packaging tools such as `pip` and `setuptools`.

### Option A: install a short global command with `pipx` (recommended for Kali Linux)

On Kali or another Debian-based system:

```bash
sudo apt update
sudo apt install -y pipx
pipx ensurepath
```

If `pipx ensurepath` says it changed your `PATH`, open a new terminal. Change into the directory that contains `pyproject.toml`, then install CASEBOOK:

```bash
cd /path/to/CASEBOOK
pipx install .
casebook --version
casebook
```

The installed command is `casebook`, even though the Python distribution package is named `casebook-dfir`.

To reinstall the local source after making changes:

```bash
pipx reinstall casebook-dfir
```

To uninstall it:

```bash
pipx uninstall casebook-dfir
```

### Option B: install into a virtual environment

Use this option when you want a project-local installation or a development environment.

**Linux / macOS:**

```bash
cd /path/to/CASEBOOK
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
casebook --version
casebook
```

**Windows PowerShell:**

```powershell
cd C:\path\to\CASEBOOK
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
casebook --version
casebook
```

### Option C: run directly from the source checkout

This uses the included launcher and does not require installing the package first:

```bash
cd /path/to/CASEBOOK
./casebook --help
./casebook --version
```

The launcher sets `PYTHONPATH` for the local `src/` package and invokes `python3 -m casebook`.

### Verify installation

```bash
casebook --version
casebook --help
casebook doctor
```

`doctor` reports the Python runtime and basic local runtime checks. Add a case path to also verify that case:

```bash
casebook doctor CASE-001
```

## Command reference

Run `casebook --help` for the complete parser-generated help available in your installed version. The reference below documents the commands implemented in version 1.0.0.

| Command | Purpose |
|---|---|
| `casebook` | Show the terminal banner and quick-start examples. |
| `casebook --version` | Print the CASEBOOK version. |
| `casebook --help` | List available commands and options. |
| `casebook init PATH [--title TEXT] [--analyst NAME] [--description TEXT]` | Initialize a case directory. The target must not already contain case data. |
| `casebook add CASE FILE [--source TEXT] [--note TEXT]` | Register a file or import a ZIP archive as original and derived evidence. |
| `casebook show [CASE]` | Show metadata and counts. `CASE` defaults to the current directory. |
| `casebook verify [CASE]` | Verify evidence files, derived members, indexes, case metadata and the audit chain. Defaults to `.`. |
| `casebook note [CASE] --text TEXT [--kind KIND] [--when ISO-8601]` | Record an analyst note. Kinds: `observation`, `action`, `decision`, `question`, `context`. |
| `casebook timeline [CASE]` | Display a case timeline. |
| `casebook finding add [CASE] --title TEXT --severity LEVEL --description TEXT [--status STATUS] [--evidence EVD-ID]...` | Record an analyst finding, optionally linked to existing evidence IDs. |
| `casebook report [CASE] [--format html\|markdown\|md\|json] [--out PATH]` | Generate a report. The default format is `html`. |
| `casebook doctor [CASE]` | Check the local runtime; if a case is supplied, also verify its integrity. |

### `init` — create a case

```bash
casebook init CASE-002 \
  --title "Authentication Log Review" \
  --analyst "styx" \
  --description "Controlled lab exercise using synthetic log exports"
```

Use a new, empty destination. CASEBOOK creates the standard case structure and records initialization in the audit journal.

### `add` — preserve evidence

```bash
casebook add CASE-002 ./auth-events.json \
  --source "isolated lab VM" \
  --note "Exported after the scenario completed"

casebook add CASE-002 ./evidence-bundle.zip \
  --source "approved training bundle" \
  --note "Contains synthetic artifacts only"
```

`FILE` can be a regular file or a ZIP file. CASEBOOK records the original input, byte size and SHA-256 digest. For ZIPs, the original archive is preserved and accepted regular members are recorded separately as derived evidence. Evidence IDs are generated by CASEBOOK; copy the IDs printed by `casebook add` when linking findings.

### `note` — record an analyst observation or action

```bash
casebook note CASE-002 \
  --kind observation \
  --text "The supplied synthetic log contains repeated authentication failures" \
  --when 2026-10-22T12:30:00Z
```

`--when` accepts ISO-8601. A value without an explicit timezone is interpreted as UTC by the current implementation; a value with a timezone is normalized to UTC. If `--when` is omitted, CASEBOOK records the current time in UTC. Record what you observed separately from what you infer.

### `finding add` — document an interpretation

```bash
casebook finding add CASE-002 \
  --title "Repeated authentication failures" \
  --severity medium \
  --status in_review \
  --description "Observed in synthetic data; validate with surrounding events." \
  --evidence EVD-0001
```

Severity must be one of `info`, `low`, `medium`, `high` or `critical`. Status must be one of `open`, `in_review`, `resolved` or `false_positive`. You can repeat `--evidence EVD-ID` to link more than one existing evidence item. Severity and status are analyst-entered labels, not automatic verdicts.

### `verify` — validate recorded integrity

```bash
casebook verify CASE-002
```

The verifier reports an overall pass/fail result and checks the records the application maintains, including file hashes and sizes, derived members, index-to-audit consistency, case initialization metadata and the local audit chain. A failed check requires investigation; verification does not silently repair evidence.

### `report` — export a portable report

```bash
casebook report CASE-002 --format html
casebook report CASE-002 --format markdown --out ./case-002-report.md
casebook report CASE-002 --format json --out ./case-002-report.json
```

Supported formats are `html`, `markdown`, the alias `md`, and `json`. If `--out` is omitted, CASEBOOK chooses a filename under the case's `reports/` directory. Existing output paths are not overwritten. A report can still be generated when integrity issues exist, but the command returns a non-zero status and the report warns about the issues; review it before use.

### `NO_COLOR` — disable ANSI color output

The terminal theme respects the [NO_COLOR convention](https://no-color.org/):

```bash
NO_COLOR=1 casebook show CASE-002
```

## End-to-end investigation example

The following is a self-contained workflow using the synthetic bundle included in the repository. Run it from the repository root after installing CASEBOOK.

```bash
# Create a case
casebook init LAB-001 \
  --title "Synthetic Evidence Handling Exercise" \
  --analyst "training-analyst" \
  --description "Demonstration using repository-provided synthetic data"

# Import the included sample bundle
casebook add LAB-001 examples/casebook-demo-bundle.zip \
  --source "CASEBOOK repository example" \
  --note "Synthetic training data; not a real incident"

# Record a note
casebook note LAB-001 \
  --kind context \
  --text "The supplied artifacts are synthetic and are used to demonstrate case handling."

# Record a finding (use an evidence ID printed by the add command)
casebook finding add LAB-001 \
  --title "Demonstration artifact recorded" \
  --severity info \
  --status resolved \
  --description "The sample bundle was imported and recorded for workflow demonstration." \
  --evidence EVD-0001

# Inspect, verify and export
casebook show LAB-001
casebook timeline LAB-001
casebook verify LAB-001
casebook report LAB-001 --format html
casebook doctor LAB-001
```

If the generated evidence ID is not `EVD-0001`, replace it with the actual ID shown by the import command. The sample data is synthetic and must not be interpreted as proof of real activity.

## Case directory layout

A newly created case starts with this structure. Files and records are added as the investigation proceeds.

```text
CASE-001/
├── case.json                       # Case ID, title, schema and initialization metadata
├── README.md                       # Case-specific notes and reminders
├── evidence/
│   ├── index.jsonl                 # Register of original evidence items
│   ├── originals/                  # Preserved input files and ZIP archives
│   └── derived/
│       └── EVD-0001/                # Accepted ZIP members associated with an item
├── findings/
│   └── findings.jsonl              # Analyst-authored findings
├── timeline/
│   └── events.jsonl                # Analyst notes and event-time annotations
├── audit/
│   └── events.jsonl                # Hash-chained local operation journal
└── reports/                        # Exported HTML, Markdown or JSON reports
```

JSON Lines means each line is a complete JSON object. Do not edit the index files manually or separately from the audit journal: CASEBOOK is designed to report divergence between these records.

## Evidence ZIP format

CASEBOOK expects a conventional ZIP archive containing **regular files in relative directories**. The archive does not need a special manifest to be imported. A suggested exchange layout is:

```text
casebook-bundle.zip
└── casebook-bundle/
    ├── README.md
    ├── manifest.json
    ├── evidence/
    │   ├── tool-export.json
    │   └── extracted-log.txt
    └── notes/
        └── acquisition-context.md
```

### Bundle guidance

- Use a clear root folder and descriptive filenames.
- Include a `README.md` with the source, acquisition method, tool/version and relevant context.
- Use relative paths. Do not add absolute paths or `../` path traversal entries.
- Keep credentials, API keys, tokens, private messages and real personal data out of public examples.
- Prefer regular files. Symbolic links and special entries are rejected.
- Do not include executable setup scripts that ask a recipient to run them.
- Treat `manifest.json` as **untrusted descriptive text**. Version 1.0.0 does not execute it or use it as trusted instructions.
- Keep the original ZIP and its derived files distinct. CASEBOOK preserves the input archive and extracts accepted members into a separate evidence tree.

### ZIP import safety limits in version 1.0.0

| Limit | Default |
|---|---:|
| Compressed archive size | 256 MiB maximum |
| Number of archive members | 2,000 maximum |
| Size of one uncompressed member | 100 MiB maximum |
| Total uncompressed member size | 512 MiB maximum |
| Compression ratio for one member | 200:1 maximum |

The importer also rejects absolute paths, traversal paths, Windows drive-qualified paths, duplicate case-insensitive member paths, encrypted members, symbolic links and special-file entries. These safeguards reduce common archive extraction risks; they do **not** prove that every malicious archive is harmless. Do not import archives from untrusted sources into an important case without appropriate isolation and backups.

## Integrity verification explained

`casebook verify CASE` checks several related records, not just a single hash:

1. **Original evidence:** checks recorded file size and SHA-256 against the bytes stored under `evidence/originals/`.
2. **Derived evidence:** checks the accepted members extracted from ZIP files.
3. **Unregistered files:** checks for unexpected files or symbolic links in locations that CASEBOOK is expected to manage.
4. **Index parity:** checks that evidence, note and finding indexes correspond to the records embedded in audit events.
5. **Audit chain:** checks sequence numbers, previous-event links and recomputed event digests.
6. **Case metadata:** checks selected initialization metadata against the initial audit record.

### What a passing result means

A passing result means the records CASEBOOK knows about are mutually consistent with the hashes and structure it verifies at that time. It does **not** prove provenance, authorship, original creation time, factual accuracy, absence of malware, or legal admissibility. An attacker who can rewrite the full local case may be able to replace records and recompute hashes.

For stronger preservation, keep a final case digest outside the case directory in a trusted location, restrict write access, use protected or immutable storage where appropriate, and document acquisition and transfer procedures separately.

## Reports

CASEBOOK supports three report data formats, with `md` as an alias for Markdown:

| Format | Intended use |
|---|---|
| HTML | A standalone, human-readable report for review in a browser. It does not require hosted fonts, scripts or remote assets. |
| Markdown | A text-based report suitable for repositories, notes, review and version-controlled documentation. |
| JSON | Structured report data for downstream processing or custom tooling. |

The report contains the case summary, evidence register, findings, timeline/audit context and an integrity summary. Review the report before sharing it because it may contain confidential investigation details. Generated reports are not digitally signed.

## Security model and limitations

### Design protections

- No evidence file is executed by CASEBOOK.
- ZIP extraction validates paths and entry types, applies size and compression-ratio limits, and stages accepted members before adding them to the case.
- Evidence files are copied and hashed; mismatched source/stored digests prevent the evidence record from being committed.
- Report rendering escapes untrusted text in HTML output.
- Existing report destinations are not silently overwritten.
- The program does not make network requests or send telemetry.

### Trust boundaries

| Component | Trust assumption and caution |
|---|---|
| Input files and ZIP members | Untrusted. Import does not make their content safe to open in another application. |
| Case directory | Local data, not encrypted by CASEBOOK. Protect it with OS permissions and full-disk encryption as appropriate. |
| Audit journal | Hash-chained but not signed or externally anchored. A sufficiently privileged local actor may rewrite the chain. |
| Analyst notes/findings | Human-authored interpretation. CASEBOOK does not validate whether the interpretation is correct. |
| Reports | Portable exports that may reveal sensitive data. Inspect them before distribution. |

### Responsible-use statement

Use CASEBOOK only with files and data you are authorized to handle. Do not use it to conceal unauthorized access, publish private data, or present a local hash as proof of an artifact's origin. This is a case-recording and integrity helper, not a certification of forensic soundness.

## Testing and development

### Run the test suite

The repository uses Python's built-in `unittest` runner. On a machine with compatible Python packaging tools, create a development environment and install the project in editable mode:

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m compileall -q src tests
python -m unittest discover -s tests -v
```

You can also run the tests from a source checkout without installing the package, by setting the local package path:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

On Windows PowerShell, use `$env:PYTHONPATH = "src"` before the unittest command. The normal installed/editable workflow is recommended for development.

### Test coverage areas

The 41 test methods in the current suite cover:

- case initialization and expected directory structure;
- original file copying, hashing and evidence ID assignment;
- missing input and symbolic-link input rejection;
- safe ZIP extraction, bad archives, path traversal and Windows drive paths;
- duplicate members, symlink members, compression ratio and path-prefix collisions;
- evidence, derived-file, metadata, index and audit tampering detection;
- note ordering, finding validation and evidence links;
- report generation, output collision handling and HTML escaping;
- CLI command workflows, expected errors, banner output and integrity verification.

**Last local test run recorded for this README:** `41 tests`, all passed using `PYTHONPATH=src python3 -m unittest discover -s tests -v`. This is a local result for the current code checkout, not a claim that a remote GitHub Actions workflow has already passed on every matrix combination.

### Continuous integration

The workflow in [`.github/workflows/tests.yml`](.github/workflows/tests.yml) is configured for:

- Operating systems: Ubuntu, Windows and macOS runners.
- Python versions: 3.10, 3.11, 3.12 and 3.13.
- Editable install, syntax compilation, the `unittest` suite and the module version entry point.

Check the [Actions tab](https://github.com/raxwqx/CASEBOOK/actions) for the latest remote run status.

## Architecture

```text
casebook CLI (argparse)
│
├── ui.py          terminal banner, theme, panels and status messages
├── core.py        case lifecycle, evidence records, notes, findings and verification
├── archive.py     ZIP validation, extraction limits and derived-file hashes
├── integrity.py   SHA-256 helpers, JSONL records and audit hash chain
└── reports.py     HTML, Markdown and JSON renderers
```

### Design principles

- **Offline by default:** no network-facing features or telemetry.
- **Standard-library runtime:** no third-party runtime dependencies.
- **Preserve originals:** keep original inputs separate from derived extraction results.
- **Explicit provenance context:** capture source and acquisition notes supplied by the analyst.
- **Fail closed for unsafe archive structures:** reject known dangerous entry patterns and configured resource-limit violations.
- **Human interpretation remains explicit:** observations, findings and automated integrity checks are distinct concepts.
- **Portable data:** UTF-8 JSON/JSONL storage and reports suitable for offline review.

More detail: [Architecture](docs/ARCHITECTURE.md) · [Case and ZIP formats](docs/FORMAT.md) · [Methodology](docs/METHODOLOGY.md) · [Security policy](SECURITY.md)

## Supported environments

| Environment | Status |
|---|---|
| Kali Linux / Debian-based Linux | Intended and suitable for terminal use with Python 3.10+ |
| Other Linux distributions | Expected to work with compatible Python; not individually certified here |
| macOS | Included in the configured CI matrix |
| Windows | Included in the configured CI matrix; use PowerShell examples for virtual environments |

CASEBOOK is a console application. Terminal support for Unicode and ANSI color varies; color can be disabled with `NO_COLOR=1`.

## Troubleshooting

### `casebook: command not found`

- If installed with `pipx`, run `pipx ensurepath` and open a new terminal.
- Confirm the install: `pipx list`.
- For source-only use, run `./casebook --help` from the project root.

### `ModuleNotFoundError: No module named 'casebook'` while running tests

Install the package into your active development environment with `python -m pip install -e .`, or run the tests with `PYTHONPATH=src` from the repository root. Ensure that you activated the intended virtual environment first.

### A ZIP import is rejected

Review the error and the bundle structure. CASEBOOK deliberately rejects absolute/traversal paths, duplicate names, symlinks and special entries, encrypted members, and archives that exceed limits. Repackage only files you are authorized to process into a conventional ZIP of regular files and try again. Do not disable checks just to force an import.

### `casebook verify` fails

Preserve the current case directory before investigating. Review the listed issue, confirm whether files or JSONL records have changed, and compare against any separately stored trusted digest or backup. CASEBOOK does not automatically repair an evidence record because silent repair could obscure what happened.

### The report exists already

CASEBOOK avoids overwriting an existing report. Choose a new path with `--out`, or move the previous report aside after you have preserved any version you need.

## Roadmap and status

**Current release line: 1.0.0.** The implemented baseline is local case management, evidence hashing, defensive ZIP import, notes/timeline, findings, integrity checks and report export.

Possible future directions, subject to design and tests, include signed export manifests, schema migration helpers and explicitly versioned adapters for known tool-output formats. These are ideas, **not features promised by the current release**. CASEBOOK does not currently provide native parsers for SPECTRA, ORBIT, TIDEWATCH or other tools; their output must be handled as files using the supported import workflow unless a verified adapter is added in a future version.

## Contributing, security reports and license

Contributions are welcome when they improve correctness, usability or safety and include tests. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Please never submit live incident evidence, real personal information, captured credentials, API keys or tokens.

For vulnerability reports, follow [SECURITY.md](SECURITY.md). Avoid publishing exploitable details before a fix is available.

Released under the [MIT License](LICENSE).

---

<a id="turkce"></a>

# 🇹🇷 Türkçe

## İçindekiler

- [CASEBOOK nedir?](#casebook-nedir)
- [Kimler için tasarlandı?](#kimler-icin-tasarlandi)
- [Özellikler](#ozellikler)
- [CASEBOOK ne yapmaz?](#casebook-ne-yapmaz)
- [Hızlı başlangıç](#hizli-baslangic)
- [Kurulum](#kurulum)
- [Komut kataloğu](#komut-katalogu)
- [Baştan sona örnek inceleme](#bastan-sona-ornek-inceleme)
- [Vaka klasörü yapısı](#vaka-klasoru-yapisi)
- [Delil ZIP biçimi](#delil-zip-bicimi)
- [Bütünlük doğrulaması nasıl çalışır?](#butunluk-dogrulamasi-nasil-calisir)
- [Raporlar](#raporlar)
- [Güvenlik modeli ve sınırlamalar](#guvenlik-modeli-ve-sinirlamalar)
- [Testler ve geliştirme](#testler-ve-gelistirme)
- [Mimari](#mimari)
- [Sorun giderme](#sorun-giderme)
- [Sürüm durumu ve yol haritası](#surum-durumu-ve-yol-haritasi)
- [Katkı, güvenlik bildirimi ve lisans](#katki-guvenlik-bildirimi-ve-lisans)

<a id="casebook-nedir"></a>

## CASEBOOK nedir?

CASEBOOK, dijital adli bilişim ve olay müdahalesi (DFIR) çalışmaları için tasarlanmış, **öncelikle çevrimdışı çalışan yerel bir vaka ve delil bütünlüğü yardımcısıdır**. Orijinal dosyaları, türetilmiş dosyaları, edinim bağlamını, analist notlarını, bulguları, zaman çizelgesini, denetim günlüğünü ve raporları tek bir standart klasör yapısında toplar.

Uzman analiz araçlarının **yerine geçmek için değil, onların yanında çalışmak için** tasarlanmıştır. Örneğin bir ağ analiz aracı veya günlük inceleme aracından alınan JSON/metin çıktısını CASEBOOK'a delil olarak ekleyebilir, kaynağını kaydedebilir ve bulgunun yorumunu belgeleyebilirsin. CASEBOOK kayıtları düzenler ve bütünlüklerini denetler; dosyayı üreten analiz motorunun yerini almaz.

### İş akışı

```text
VAKA OLUŞTUR
    ↓
DOSYA VEYA ZIP PAKETİ EKLE
    ↓
ORİJİNALİ KORU + SHA-256 HESAPLA
    ↓
NOTLARI, OLAYLARI VE BULGULARI KAYDET
    ↓
DOSYALARI, İNDEKSLERİ VE DENETİM ZİNCİRİNİ DOĞRULA
    ↓
HTML / MARKDOWN / JSON RAPORU ÜRET
```

<a id="kimler-icin-tasarlandi"></a>

## Kimler için tasarlandı?

- **Öğrenciler ve laboratuvar kullanıcıları:** Tekrarlanabilir, sentetik inceleme senaryoları hazırlamak için.
- **Siber güvenlik analistleri:** Dosyaları, gözlemleri ve araç çıktılarıyla ilişkili bulguları yerelde düzenlemek için.
- **DFIR uygulayıcıları:** Kaynak dosyalar ile çıkarılmış/türetilmiş dosyaları ve analist yorumlarını birbirinden ayırmak için.
- **Güvenlik aracı geliştiricileri:** Kendi analiz araçlarından alınan çıktıları vaka kaydına dönüştürmek için.

Yalnızca işlemeye yetkili olduğun dosyaları kullan. Gösterim ve testlerde sentetik verileri tercih et.

<a id="ozellikler"></a>

## Özellikler

| Özellik | Pratikte ne sağlar? |
|---|---|
| Düzenli vaka yapısı | Vaka metadatası, orijinal deliller, türetilmiş deliller, bulgular, notlar, denetim kayıtları ve raporları ayrı tutar. |
| Orijinal dosyayı koruma | Girdi dosyasını vakaya kopyalar. Kaynak ve kopya için SHA-256 hesaplar; özetler uyuşmazsa kaydı tamamlamaz. |
| SHA-256 envanteri | Deliller ve kabul edilen ZIP üyeleri için hash ve bayt cinsinden boyut kaydeder. |
| Savunmacı ZIP içe aktarma | Güvensiz yolları, sembolik bağlantıları/özel dosyaları, yinelenen yolları, şifreli üyeleri ve belirlenen kaynak sınırlarını aşan arşivleri reddeder. |
| Türetilmiş deliller | Kabul edilen ZIP üyelerini ayrı bir klasöre çıkarır ve orijinal ZIP'i korur. |
| İncelenebilir kayıtlar | JSON ve JSON Lines (`.jsonl`) verileri metin olarak okunabilir tutar. |
| Hash zincirli denetim günlüğü | Her olay önceki olayla bağlantılı bir özet taşır; doğrulama sıralamayı ve bağlantıları kontrol eder. |
| Notlar ve zaman çizelgesi | Analist notlarını türü ve UTC'ye normalize edilmiş olay zamanı ile kaydeder. |
| Delille ilişkilendirilen bulgular | Önem derecesi, durum, açıklama ve mevcut delil kimlikleriyle ilişkilendirilmiş analist bulguları tutar. |
| Taşınabilir raporlar | Bağımsız HTML, Markdown veya JSON raporları oluşturur; var olan dosyaların üzerine sessizce yazmaz. |
| Yerel çalışma | CASEBOOK ağ isteği, telemetri, kullanıcı hesabı, uzak API veya üçüncü taraf çalışma zamanı bağımlılığı kullanmaz. |
| Test ve CI altyapısı | Python'ın yerleşik `unittest` testlerini ve Linux/macOS/Windows için yapılandırılmış GitHub Actions matrisini içerir. |

<a id="casebook-ne-yapmaz"></a>

## CASEBOOK ne yapmaz?

CASEBOOK'in kapsamı bilerek sınırlı tutulmuştur. Program:

- canlı bellek, disk imajı veya uçucu sistem durumu edinmez;
- PCAP/PCAPNG ayrıştırmaz, canlı ağ denetlemez, port taramaz veya keşif (reconnaissance) yapmaz;
- hesaplara giriş yapmaz, posta kutularına erişmez, verilerin şifresini çözmez veya erişim denetimlerini aşmaz;
- delil olarak içe aktarılan dosyaları çalıştırmaz;
- bir dosyayı otomatik olarak zararlı ilan etmez veya olayın ne olduğunu kendiliğinden belirlemez;
- dosyanın sahibini, gerçek oluşturulma zamanını, içeriğinin doğruluğunu veya hukuki geçerliliğini kanıtlamaz;
- vakayı dijital olarak imzalamaz, güvenilir zaman damgası sağlamaz, vaka klasörünü şifrelemez veya adli geçerlilik garantisi vermez.

Edinim ve teknik analiz için amaca uygun araçlar kullan. Gerektiğinde aracın adını, sürümünü, kaynağını, yöntemini ve ilgili bağlamı analist notlarına kaydet.

<a id="hizli-baslangic"></a>

## Hızlı başlangıç

Aşağıdaki komutlar CASEBOOK kurulu olduğunu ve `casebook` komutunun `PATH` içinde bulunduğunu varsayar.

```bash
# 1. Bir vaka oluştur
casebook init CASE-001 --title "Egitim Laboratuvari" --analyst "analist-adi"

# 2. Depoyla gelen sentetik demo paketini ekle
casebook add CASE-001 examples/casebook-demo-bundle.zip \
  --source "CASEBOOK sentetik demo" \
  --note "Eğitim amacıyla hazırlanmış sentetik veri; gerçek olay delili değildir"

# 3. Kayıtlı bütünlüğü denetle
casebook verify CASE-001

# 4. Bağımsız HTML raporu oluştur
casebook report CASE-001 --format html

# 5. Vaka özetini ve zaman çizelgesini incele
casebook show CASE-001
casebook timeline CASE-001
```

`--out` verilmediyse HTML raporu vakanın `reports/` klasörüne kaydedilir. Raporlar dosya adlarını, gözlemleri, bulguları ve hassas inceleme ayrıntılarını içerebilir; paylaşmadan önce kontrol et.

### Alternatif: vaka klasörüne girerek kullan

```bash
casebook init CASE-001 --title "Egitim Laboratuvari"
cd CASE-001
casebook add . ../examples/casebook-demo-bundle.zip --source "sentetik demo"
casebook verify .
casebook report . --format html
```

Bu örnekte `CASE-001/` klasörü ile `examples/` klasörünün proje dizini altında kardeş klasörler olduğu varsayılır.

<a id="kurulum"></a>

## Kurulum

### Gereksinimler

- Python **3.10 veya daha yeni bir sürüm**.
- Uyumlu Python kurulumuna sahip Linux, macOS veya Windows.
- Üçüncü taraf **çalışma zamanı** paketi gerekmez.
- Geliştirme sırasında proje düzenlenebilir (editable) kurulumla yüklenir ve testler Python'ın yerleşik `unittest` çerçevesini kullanır. Kaynaktan kurulum/paket oluşturma için `pip` ve `setuptools` gibi standart paketleme araçları gerekebilir.

### Seçenek A: `pipx` ile kısa bir genel komut kur (Kali Linux için önerilir)

Kali veya Debian tabanlı sistemde:

```bash
sudo apt update
sudo apt install -y pipx
pipx ensurepath
```

`pipx ensurepath` `PATH` ayarını değiştirdiğini söylerse yeni bir terminal aç. `pyproject.toml` dosyasının bulunduğu proje dizinine geç ve yükle:

```bash
cd /path/to/CASEBOOK
pipx install .
casebook --version
casebook
```

Kullanacağın komutun adı `casebook`, Python dağıtım paketinin adı ise `casebook-dfir` olarak tanımlanmıştır.

Yerel kaynak kodunda değişiklik yaptıktan sonra yeniden kurmak için:

```bash
pipx reinstall casebook-dfir
```

Kaldırmak için:

```bash
pipx uninstall casebook-dfir
```

### Seçenek B: sanal ortama kur

Proje klasörüne özel kurulum veya geliştirme ortamı istediğinde bunu kullan.

**Linux / macOS:**

```bash
cd /path/to/CASEBOOK
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
casebook --version
casebook
```

**Windows PowerShell:**

```powershell
cd C:\path\to\CASEBOOK
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
casebook --version
casebook
```

### Seçenek C: kaynak kodundan doğrudan çalıştır

Bu yöntem paket yüklemeden, depodaki başlatıcıyı kullanır:

```bash
cd /path/to/CASEBOOK
./casebook --help
./casebook --version
```

Başlatıcı yerel `src/` klasörü için `PYTHONPATH` ayarlar ve `python3 -m casebook` komutunu çağırır.

### Kurulumu doğrula

```bash
casebook --version
casebook --help
casebook doctor
```

`doctor`, Python çalışma zamanını ve temel yerel ortam kontrollerini raporlar. Bir vaka yolu verirsen o vakanın bütünlüğünü de kontrol eder:

```bash
casebook doctor CASE-001
```

<a id="komut-katalogu"></a>

## Komut kataloğu

Kurulu sürümdeki tam seçenekleri görmek için `casebook --help` komutunu çalıştır. Aşağıdaki tablo 1.0.0 sürümünde uygulanan komutları açıklar.

| Komut | Amacı |
|---|---|
| `casebook` | Terminal başlığını ve hızlı başlangıç örneklerini gösterir. |
| `casebook --version` | CASEBOOK sürümünü gösterir. |
| `casebook --help` | Komutları ve seçenekleri listeler. |
| `casebook init PATH [--title TEXT] [--analyst NAME] [--description TEXT]` | Yeni bir vaka klasörü oluşturur. Hedefte önceden vaka verisi bulunmamalıdır. |
| `casebook add CASE FILE [--source TEXT] [--note TEXT]` | Dosyayı kaydeder veya ZIP arşivini güvenli biçimde içe aktarır. |
| `casebook show [CASE]` | Vaka metadatasını ve kayıt sayılarını gösterir. Varsayılan yol geçerli klasördür. |
| `casebook verify [CASE]` | Delilleri, türetilmiş üyeleri, indeksleri, vaka metadatasını ve denetim zincirini doğrular. Varsayılan `.` olur. |
| `casebook note [CASE] --text TEXT [--kind KIND] [--when ISO-8601]` | Analist notu ekler. Türler: `observation`, `action`, `decision`, `question`, `context`. |
| `casebook timeline [CASE]` | Vaka zaman çizelgesini gösterir. |
| `casebook finding add [CASE] --title TEXT --severity LEVEL --description TEXT [--status STATUS] [--evidence EVD-ID]...` | İsteğe bağlı olarak mevcut delil kimliklerine bağlanan bir bulgu ekler. |
| `casebook report [CASE] [--format html\|markdown\|md\|json] [--out PATH]` | Rapor üretir. Varsayılan biçim `html` olur. |
| `casebook doctor [CASE]` | Ortamı denetler; vaka yolu verilirse vakanın bütünlüğünü de kontrol eder. |

### `init` — vaka oluşturma

```bash
casebook init CASE-002 \
  --title "Kimlik Dogrulama Gunlugu Incelemesi" \
  --analyst "styx" \
  --description "Sentetik günlük dışa aktarımlarıyla kontrollü laboratuvar çalışması"
```

Yeni ve boş bir hedef klasör kullan. CASEBOOK standart klasörleri oluşturur ve başlangıç olayını denetim günlüğüne kaydeder.

### `add` — delili koruma

```bash
casebook add CASE-002 ./auth-events.json \
  --source "izole laboratuvar VM" \
  --note "Senaryo tamamlandıktan sonra dışa aktarıldı"

casebook add CASE-002 ./evidence-bundle.zip \
  --source "izinli eğitim paketi" \
  --note "Yalnızca sentetik örnekler içerir"
```

`FILE` normal bir dosya veya ZIP olabilir. CASEBOOK girdiyi orijinal delil olarak saklar, boyutunu ve SHA-256 özetini kaydeder. ZIP için orijinal arşiv korunur; kabul edilen normal dosyalar ayrı bir türetilmiş delil konumuna çıkarılır ve kaydedilir. Delil kimliklerini CASEBOOK üretir; bulgu eklerken `casebook add` çıktısındaki kimliği kullan.

### `note` — gözlem veya işlemi kaydetme

```bash
casebook note CASE-002 \
  --kind observation \
  --text "Verilen sentetik günlükte tekrarlanan kimlik doğrulama hataları var" \
  --when 2026-10-22T12:30:00Z
```

`--when` ISO-8601 biçimini kabul eder. Zaman dilimi belirtilmemiş değer mevcut uygulamada UTC kabul edilir; zaman dilimi belirtilen değer UTC'ye dönüştürülür. `--when` verilmezse o anki UTC zamanı kaydedilir. Gözlemlediğin şeyi, çıkardığın yorumdan ayrı tut.

### `finding add` — yorumu bulgu olarak belgeleme

```bash
casebook finding add CASE-002 \
  --title "Tekrarlanan kimlik doğrulama hataları" \
  --severity medium \
  --status in_review \
  --description "Sentetik veride gözlendi; çevresindeki olaylarla doğrulanmalı." \
  --evidence EVD-0001
```

Önem derecesi `info`, `low`, `medium`, `high` veya `critical` olmalıdır. Durum `open`, `in_review`, `resolved` veya `false_positive` olabilir. Birden fazla mevcut delili ilişkilendirmek için `--evidence EVD-ID` seçeneğini tekrarla. Önem derecesi ve durum analistin belirlediği etiketlerdir, otomatik hüküm değildir.

### `verify` — kayıtlı bütünlüğü doğrulama

```bash
casebook verify CASE-002
```

Doğrulayıcı tek bir hash'e değil, uygulamanın tuttuğu ilişkili kayıtlara bakar. Dosya boyutları ve hash'ler, türetilmiş üyeler, indeks-denetim günlüğü tutarlılığı, başlangıç metadatası ve yerel denetim zinciri kontrol edilir. Başarısız bir kontrol araştırılmalıdır; doğrulama delili sessizce onarmaz.

### `report` — taşınabilir rapor oluşturma

```bash
casebook report CASE-002 --format html
casebook report CASE-002 --format markdown --out ./case-002-report.md
casebook report CASE-002 --format json --out ./case-002-report.json
```

Desteklenen biçimler `html`, `markdown`, `md` kısaltması ve `json` olur. `--out` verilmezse vaka içindeki `reports/` klasöründe bir dosya adı seçilir. Var olan hedef dosyanın üzerine yazılmaz. Bütünlük sorunu varsa rapor yine üretilebilir; ancak komut sıfır dışı çıkış kodu döndürür ve raporda uyarı bulunur. Kullanımdan önce raporu incele.

### `NO_COLOR` — ANSI renklerini kapatma

Terminal teması [NO_COLOR yaklaşımına](https://no-color.org/) uyar:

```bash
NO_COLOR=1 casebook show CASE-002
```

<a id="bastan-sona-ornek-inceleme"></a>

## Baştan sona örnek inceleme

Aşağıdaki akış depoda bulunan sentetik paketi kullanır. CASEBOOK kurulduktan sonra komutları proje kök dizininden çalıştır.

```bash
# Vaka oluştur
casebook init LAB-001 \
  --title "Sentetik Delil Isleme Calismasi" \
  --analyst "egitim-analisti" \
  --description "Depoda sağlanan sentetik verilerle gösterim"

# Örnek paketi içe aktar
casebook add LAB-001 examples/casebook-demo-bundle.zip \
  --source "CASEBOOK depo örneği" \
  --note "Sentetik eğitim verisi; gerçek olay değildir"

# Not ekle
casebook note LAB-001 \
  --kind context \
  --text "Sağlanan dosyalar sentetiktir ve iş akışını göstermek amacıyla kullanılır."

# Bir bulgu ekle (add komutunun yazdırdığı delil kimliğini kullan)
casebook finding add LAB-001 \
  --title "Gösterim dosyası kaydedildi" \
  --severity info \
  --status resolved \
  --description "Örnek paket, iş akışını göstermek için içe aktarıldı ve kaydedildi." \
  --evidence EVD-0001

# İncele, doğrula ve raporla
casebook show LAB-001
casebook timeline LAB-001
casebook verify LAB-001
casebook report LAB-001 --format html
casebook doctor LAB-001
```

Üretilen delil kimliği `EVD-0001` değilse kendi `add` çıktındaki kimliği kullan. Örnek veriler sentetiktir; gerçek bir faaliyetin kanıtı olarak yorumlanmamalıdır.

<a id="vaka-klasoru-yapisi"></a>

## Vaka klasörü yapısı

Yeni vaka şu yapıyla başlar. Dosyalar ve kayıtlar inceleme ilerledikçe eklenir.

```text
CASE-001/
├── case.json                       # Vaka kimliği, başlık, şema ve başlangıç metadatası
├── README.md                       # Vakaya özel notlar ve hatırlatmalar
├── evidence/
│   ├── index.jsonl                 # Orijinal delil envanteri
│   ├── originals/                  # Korunan kaynak dosyaları ve ZIP arşivleri
│   └── derived/
│       └── EVD-0001/                # Bir delile bağlı kabul edilmiş ZIP üyeleri
├── findings/
│   └── findings.jsonl              # Analist tarafından yazılan bulgular
├── timeline/
│   └── events.jsonl                # Notlar ve olay zamanı kayıtları
├── audit/
│   └── events.jsonl                # Hash zincirli yerel işlem günlüğü
└── reports/                        # HTML, Markdown veya JSON dışa aktarımları
```

JSON Lines biçiminde her satır eksiksiz bir JSON nesnesidir. İndeks dosyalarını denetim günlüğünden bağımsız olarak elle düzenleme; CASEBOOK bu kayıtlar arasındaki uyumsuzluğu bildirmek üzere tasarlanmıştır.

<a id="delil-zip-bicimi"></a>

## Delil ZIP biçimi

CASEBOOK, **göreli klasör yollarında normal dosyalar** barındıran standart bir ZIP arşivi bekler. İçe aktarma için özel bir manifest zorunlu değildir. Önerilen paket düzeni:

```text
casebook-bundle.zip
└── casebook-bundle/
    ├── README.md
    ├── manifest.json
    ├── evidence/
    │   ├── tool-export.json
    │   └── extracted-log.txt
    └── notes/
        └── acquisition-context.md
```

### Paket hazırlama önerileri

- Anlamlı bir kök klasör ve açıklayıcı dosya adları kullan.
- Kaynağı, edinim yöntemini, araç/sürüm bilgisini ve bağlamı belirten bir `README.md` ekle.
- Göreli yollar kullan; mutlak yollar veya `../` ile dizin dışına çıkmaya çalışan girdiler ekleme.
- Kimlik bilgilerini, API anahtarlarını, token'ları, özel mesajları ve gerçek kişisel verileri herkese açık örneklere koyma.
- Normal dosyaları tercih et. Sembolik bağlantılar ve özel dosya girdileri reddedilir.
- Alıcıdan çalıştırmasını isteyen çalıştırılabilir kurulum betiklerini pakete ekleme.
- `manifest.json` dosyasını **güvenilmeyen açıklayıcı metin** olarak gör. 1.0.0 sürümü bunu çalıştırmaz veya güvenilir talimat kabul etmez.
- Orijinal ZIP'i çıkarılan dosyalardan ayrı tut. CASEBOOK giriş arşivini korur ve kabul edilen üyeleri ayrı bir delil ağacına çıkarır.

### 1.0.0 sürümündeki ZIP sınırları

| Sınır | Varsayılan değer |
|---|---:|
| Sıkıştırılmış arşiv boyutu | En fazla 256 MiB |
| Arşiv üyesi sayısı | En fazla 2.000 |
| Tek bir üyenin açılmış boyutu | En fazla 100 MiB |
| Tüm üyelerin toplam açılmış boyutu | En fazla 512 MiB |
| Tek bir üyenin sıkıştırma oranı | En fazla 200:1 |

İçe aktarıcı ayrıca mutlak yolları, dizin dışına çıkan yolları, Windows sürücü harfiyle başlayan yolları, büyük/küçük harf duyarsız yinelenen üye yollarını, şifreli üyeleri, sembolik bağlantıları ve özel dosya girdilerini reddeder. Bu önlemler yaygın arşiv açma risklerini azaltır; her kötü amaçlı arşivin zararsız olduğunu **kanıtlamaz**. Kaynağı güvenilir olmayan arşivleri önemli bir vakaya almadan önce uygun izolasyon ve yedekleme kullan.

<a id="butunluk-dogrulamasi-nasil-calisir"></a>

## Bütünlük doğrulaması nasıl çalışır?

`casebook verify CASE`, tek bir hash yerine birbiriyle ilişkili birkaç kayıt grubunu denetler:

1. **Orijinal delil:** `evidence/originals/` içindeki dosyanın boyutunu ve SHA-256 değerini kaydedilen değerlerle karşılaştırır.
2. **Türetilmiş delil:** ZIP'ten çıkarılıp kabul edilen üyeleri denetler.
3. **Kayıtsız dosyalar:** CASEBOOK'un yönettiği konumlarda beklenmeyen dosya veya sembolik bağlantı olup olmadığını kontrol eder.
4. **İndeks tutarlılığı:** Delil, not ve bulgu indekslerinin denetim olaylarında tutulan kayıtlarla eşleşmesini denetler.
5. **Denetim zinciri:** Sıra numaralarını, önceki olay bağlantılarını ve olay özetlerini kontrol eder.
6. **Vaka metadatası:** Bazı başlangıç alanlarını ilk denetim kaydıyla karşılaştırır.

### Başarılı doğrulama ne anlama gelir?

Başarılı sonuç, o anda CASEBOOK'un tanıdığı ve denetlediği kayıtların, kaydedilmiş özetler ve yapı ile tutarlı olduğu anlamına gelir. Dosyanın kökenini, yazarı, ilk oluşturulma zamanını, içeriğin doğruluğunu, zararsızlığını veya hukuki geçerliliğini kanıtlamaz. Yerel vakanın tamamını yazma yetkisi olan bir kişi kayıtları değiştirip hash'leri yeniden hesaplayabilir.

Daha güçlü koruma için vaka dışındaki güvenilir bir konumda nihai vaka özeti sakla; yazma erişimini sınırla; uygun olduğunda korumalı veya değiştirilemez depolama kullan; edinim ve aktarım adımlarını ayrıca belgele.

<a id="raporlar"></a>

## Raporlar

CASEBOOK `md` kısaltmasıyla birlikte üç rapor veri biçimini destekler:

| Biçim | Kullanım amacı |
|---|---|
| HTML | Tarayıcıda incelenebilen bağımsız, okunabilir rapor. Harici yazı tipi, betik veya uzak kaynağa ihtiyaç duymaz. |
| Markdown | Depolarda, notlarda, incelemede ve sürüm kontrollü belgelerde kullanılabilecek metin raporu. |
| JSON | Sonraki işleme veya özel araçlar için yapılandırılmış rapor verisi. |

Rapor; vaka özetini, delil listesini, bulguları, zaman çizelgesi/denetim bağlamını ve bütünlük özetini içerir. Raporlar gizli inceleme ayrıntıları taşıyabilir; paylaşmadan önce incele. Üretilen raporlar dijital olarak imzalanmaz.

<a id="guvenlik-modeli-ve-sinirlamalar"></a>

## Güvenlik modeli ve sınırlamalar

### Tasarımdaki korumalar

- CASEBOOK hiçbir delil dosyasını çalıştırmaz.
- ZIP çıkarımı yolları ve girdi türlerini doğrular, boyut/sıkıştırma sınırlarını uygular ve kabul edilen üyeleri vakaya eklemeden önce geçici alanda hazırlar.
- Delil dosyaları kopyalanır ve hash'lenir; kaynak ile kopyanın hash'i farklıysa kayıt tamamlanmaz.
- HTML rapor oluşturma sırasında güvenilmeyen metinler kaçışlama işleminden geçirilir.
- Var olan rapor hedeflerinin üzerine sessizce yazılmaz.
- Program ağ isteği yapmaz ve telemetri göndermez.

### Güven sınırları

| Bileşen | Güven varsayımı ve dikkat |
|---|---|
| Girdi dosyaları ve ZIP üyeleri | Güvenilmez. İçe aktarmak, dosyanın başka bir uygulamada açılmasını güvenli hâle getirmez. |
| Vaka klasörü | CASEBOOK tarafından şifrelenmez. Uygun olduğunda işletim sistemi izinleri ve tam disk şifrelemesiyle koru. |
| Denetim günlüğü | Hash zincirlidir; imzalı veya harici güvenilir kaynağa sabitlenmiş değildir. Yerel yazma yetkisi olan biri zinciri yeniden oluşturabilir. |
| Analist notları/bulguları | İnsan tarafından yazılmış yorumlardır. CASEBOOK bunların doğruluğunu doğrulamaz. |
| Raporlar | Hassas verileri açığa çıkarabilecek taşınabilir çıktılardır. Dağıtmadan önce denetle. |

### Sorumlu kullanım

CASEBOOK'u yalnızca işlemeye yetkili olduğun dosyalarla kullan. Yetkisiz erişimi gizlemek, özel verileri yayımlamak veya yerel bir hash'i dosyanın kökeninin kanıtı gibi sunmak için kullanma. CASEBOOK vaka kayıt ve bütünlük yardımcısıdır; adli sağlamlık sertifikası değildir.

<a id="testler-ve-gelistirme"></a>

## Testler ve geliştirme

### Test takımını çalıştır

Depoda Python'ın yerleşik `unittest` test çalıştırıcısı kullanılır. Python paketleme araçlarının bulunduğu bir sistemde geliştirme ortamı oluştur ve projeyi düzenlenebilir kipte kur:

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m compileall -q src tests
python -m unittest discover -s tests -v
```

Paketi kurmadan, kaynak kodu üzerinden test etmek de mümkündür:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Windows PowerShell'de `unittest` komutundan önce `$env:PYTHONPATH = "src"` ayarla. Geliştirme için normal kurulum/düzenlenebilir kurulum akışı önerilir.

### Test kapsamındaki alanlar

Mevcut test takımındaki 41 test metodu şu konuları kapsar:

- vaka başlangıcı ve beklenen klasör yapısı;
- orijinal dosya kopyalama, hash hesaplama ve delil kimliği atama;
- eksik girdi ve sembolik bağlantı girdi reddi;
- güvenli ZIP çıkarımı, bozuk arşiv, yol aşımı ve Windows sürücü yolları;
- yinelenen üyeler, sembolik bağlantı üyeleri, sıkıştırma oranı ve yol öneki çakışmaları;
- delil, türetilmiş dosya, metadata, indeks ve denetim kaydı değişikliklerinin tespiti;
- not sıralaması, bulgu doğrulama ve delil bağlantıları;
- rapor oluşturma, var olan hedefi koruma ve HTML kaçışlama;
- CLI iş akışları, beklenen hatalar, başlangıç ekranı ve bütünlük doğrulaması.

**Bu README için son yerel test sonucu:** `PYTHONPATH=src python3 -m unittest discover -s tests -v` komutu ile `41 tests` çalıştı ve tamamı geçti. Bu, mevcut kaynak kodu üzerindeki yerel sonuçtur; uzak GitHub Actions iş akışının tüm matris kombinasyonlarında geçtiği iddiası değildir.

### Sürekli entegrasyon (CI)

[`.github/workflows/tests.yml`](.github/workflows/tests.yml) iş akışı şu kombinasyonlar için yapılandırılmıştır:

- İşletim sistemleri: Ubuntu, Windows ve macOS.
- Python sürümleri: 3.10, 3.11, 3.12 ve 3.13.
- Düzenlenebilir kurulum, sözdizimi derlemesi, `unittest` takımı ve modül sürüm komutu.

Uzak çalıştırmaların en güncel durumunu [Actions sekmesinden](https://github.com/raxwqx/CASEBOOK/actions) kontrol et.

<a id="mimari"></a>

## Mimari

```text
casebook CLI (argparse)
│
├── ui.py          terminal başlığı, tema, paneller ve durum mesajları
├── core.py        vaka yaşam döngüsü, deliller, notlar, bulgular ve doğrulama
├── archive.py     ZIP doğrulaması, çıkarma sınırları ve türetilmiş dosya hash'leri
├── integrity.py   SHA-256 yardımcıları, JSONL kayıtları ve denetim hash zinciri
└── reports.py     HTML, Markdown ve JSON rapor oluşturucular
```

### Tasarım ilkeleri

- **Varsayılan olarak çevrimdışı:** ağ üzerinden özellik veya telemetri yoktur.
- **Standart kütüphane ile çalışma:** üçüncü taraf çalışma zamanı bağımlılığı yoktur.
- **Orijinalleri koruma:** giriş dosyaları türetilmiş çıkarım sonuçlarından ayrı tutulur.
- **Kaynak bağlamını açık tutma:** analistin sağladığı kaynak ve edinim notları kaydedilir.
- **Güvensiz arşivlerde güvenli tarafta kalma:** bilinen tehlikeli girdi biçimleri ve kaynak limitleri reddedilir.
- **İnsan yorumunu ayrı tutma:** gözlemler, bulgular ve otomatik bütünlük denetimleri birbirinden ayrıdır.
- **Taşınabilir veri:** çevrimdışı incelemeye uygun UTF-8 JSON/JSONL kayıtları ve raporlar.

Daha fazla ayrıntı: [Mimari](docs/ARCHITECTURE.md) · [Vaka ve ZIP biçimleri](docs/FORMAT.md) · [Yöntem](docs/METHODOLOGY.md) · [Güvenlik politikası](SECURITY.md)

## Desteklenen ortamlar

| Ortam | Durum |
|---|---|
| Kali Linux / Debian tabanlı Linux | Python 3.10+ ile terminal kullanımına uygun |
| Diğer Linux dağıtımları | Uyumlu Python ile çalışması beklenir; burada ayrı ayrı sertifikalandırılmamıştır |
| macOS | Yapılandırılmış CI matrisine dahildir |
| Windows | Yapılandırılmış CI matrisine dahildir; sanal ortam örneklerinde PowerShell kullanılır |

CASEBOOK bir konsol uygulamasıdır. Unicode ve ANSI renk desteği terminale göre değişebilir; `NO_COLOR=1` ile renkleri kapatabilirsin.

<a id="sorun-giderme"></a>

## Sorun giderme

### `casebook: command not found`

- `pipx` ile kurduysan `pipx ensurepath` çalıştır ve yeni terminal aç.
- Kurulumu `pipx list` ile kontrol et.
- Yalnızca kaynak kodunu kullanıyorsan proje kökünden `./casebook --help` çalıştır.

### Testleri çalıştırırken `ModuleNotFoundError: No module named 'casebook'`

Aktif geliştirme ortamına `python -m pip install -e .` ile yükle veya depoda `PYTHONPATH=src` ile test komutunu çalıştır. Doğru sanal ortamı etkinleştirdiğinden emin ol.

### ZIP içe aktarma reddediliyor

Hata mesajını ve paket yapısını incele. CASEBOOK mutlak/dizin dışına çıkan yolları, yinelenen adları, sembolik bağlantıları ve özel girdileri, şifreli üyeleri ve limitleri aşan arşivleri kasıtlı olarak reddeder. Gerekirse yalnızca işlemeye yetkili olduğun dosyaları normal dosyalardan oluşan standart bir ZIP'e yeniden paketle. İçe aktarmayı zorlamak için kontrolleri devre dışı bırakma.

### `casebook verify` başarısız

İncelemeye başlamadan önce mevcut vaka klasörünü koru. Listelenen sorunu incele, dosya veya JSONL kayıtlarının değişip değişmediğini kontrol et ve varsa harici güvenilir özet ya da yedek ile karşılaştır. Sessiz onarım adli kaydın geçmişini gizleyebileceği için CASEBOOK delil kaydını otomatik onarmaz.

### Rapor dosyası zaten var

CASEBOOK var olan raporun üzerine yazmaz. `--out` ile yeni bir yol belirle veya gerekli eski raporu koruduktan sonra başka yere taşı.

<a id="surum-durumu-ve-yol-haritasi"></a>

## Sürüm durumu ve yol haritası

**Mevcut sürüm hattı: 1.0.0.** Uygulanan temel özellikler yerel vaka yönetimi, delil hash'leme, savunmacı ZIP içe aktarma, notlar/zaman çizelgesi, bulgular, bütünlük denetimleri ve rapor dışa aktarmadır.

Gelecekte değerlendirilebilecek geliştirmeler arasında imzalı dışa aktarma manifestoları, şema geçiş yardımcıları ve bilinen araç çıktı biçimleri için açıkça sürümlenmiş bağdaştırıcılar bulunabilir. Bunlar fikir aşamasındadır; mevcut sürümün sunduğu özellikler değildir. CASEBOOK şu anda SPECTRA, ORBIT, TIDEWATCH veya diğer araçlar için yerleşik ayrıştırıcı sağlamaz. Gelecekte doğrulanmış bir bağdaştırıcı eklenmediği sürece bu araçların çıktıları desteklenen dosya içe aktarma iş akışıyla eklenmelidir.

<a id="katki-guvenlik-bildirimi-ve-lisans"></a>

## Katkı, güvenlik bildirimi ve lisans

Doğruluğu, kullanılabilirliği veya güvenliği artıran ve testlerle desteklenen katkılar memnuniyetle karşılanır. Pull request açmadan önce [CONTRIBUTING.md](CONTRIBUTING.md) belgesini oku. Gerçek olay delillerini, kişisel bilgileri, yakalanmış kimlik bilgilerini, API anahtarlarını veya token'ları asla depoya ekleme.

Güvenlik açığı bildirimleri için [SECURITY.md](SECURITY.md) yönergesini izle. Düzeltme yayımlanmadan önce istismar ayrıntılarını kamuya açık şekilde paylaşmaktan kaçın.

Proje [MIT Lisansı](LICENSE) ile yayımlanmıştır.

---

<div align="center">

**CASEBOOK · Keep the evidence. Document the reasoning. Verify the record.**

**CASEBOOK · Delili koru. Gerekçeyi belgele. Kaydı doğrula.**

</div>
