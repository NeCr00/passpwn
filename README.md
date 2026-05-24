<div align="center">

# `passpwn`

*Builds spray-ready and per-user wordlists from a target's own context — ranked by patterns observed in real-world breach data.*

</div>

---

## What It Does

`passpwn` consumes whatever you already know about a target — company name and variants, address tokens, employees' names, usernames, custom keywords — and emits **two complementary wordlists**:

| File | Format | Use for |
|---|---|---|
| **`spray.txt`** | one password per line | password **spraying**: one password tried across many accounts |
| **`user_pass.txt`** | `username:password` per line | **targeted brute force**: each account gets its own candidate set |

Both lists are sorted **most-likely-first** so that limited attempts (think: 3 tries per account before lockout) hit the highest-probability candidates.

---

## Why This Approach Works

`passpwn` doesn't guess randomly. The mutation engine encodes patterns documented in published breach analyses and password-cracking research:

- **The dominant mask is `?u?l?l?l?l?l?d?d?s`** — Upper + lowers + digits + symbol (e.g. `Summer18!`). A handful of masks like this cover roughly half of real-world enterprise passwords. *(Praetorian.)*
- **>90% of users place the uppercase letter first** when forced to satisfy a complexity rule. *(Praetorian.)*
- **People append, they don't prepend.** Digits and symbols go at the end. Prefixes are rare. *(clem9669 / hashcat rule research.)*
- **The company-name effect is real.** Roughly 20% of breached corporate passwords contain the company's name or a slight variation. *(Fortune-500 breach analysis.)*
- **Forced rotation produces seasonal/year patterns.** `Winter2024!`, `Spring2025!`, `Summer25#` dominate sprays against orgs with periodic resets. *(Horizon3.ai, ESET.)*
- **Top global breach base words** like `password`, `admin`, `welcome`, `letmein`, `qwerty`, `p@ssw0rd` still show up in every industry. *(NordPass / Specops / Cybernews 2025.)*

The generator builds these patterns from *your* inputs and emits them in real-world priority order — so the top of the spray list is the highest-ROI guess, not random noise.

---

## Installation

```bash
git clone <repo>  # or just copy passpwn.py
cd passpwn
chmod +x passpwn.py
./passpwn.py --help
```

Requires **Python 3.9+**, standard library only. No pip, no virtualenv, no dependencies.

---

## Quick Start

A minimal run that produces both lists:

```bash
./passpwn.py \
  --company-words "Acme,AcmeCorp,acme-inc" \
  --names people.txt \
  --complexity ulds \
  --out-spray spray.txt \
  --out-user-pass user_pass.txt
```

Verbose, with all inputs:

```bash
./passpwn.py \
  --company-words "Acme,AcmeCorp,acme-inc" \
  --addresses "350 Fifth Ave,New York,10118" \
  --usernames users.txt \
  --names people.txt \
  --custom keywords.txt \
  --years 2022-2026 \
  --complexity ulds --min-length 8 --max-length 16 \
  --max-spray 5000 --max-per-user 50 \
  --out-spray spray.txt --out-user-pass user_pass.txt \
  --verbose
```

---

## Inputs in detail

At least **one** input source is required. They're additive — pass any combination.

### `--company-words "csv,of,words"`

Comma-separated tokens. Whitespace and `-` / `_` separators split into pieces, and the joined form is added too. Example:

```bash
--company-words "Acme,Acme Corp,acme-inc,ACME Holdings"
```

produces the base words: `acme`, `corp`, `acmecorp`, `inc`, `acmeinc`, `holdings`, `acmeholdings`.

### `--company-file <path>`

Same as `--company-words` but read from a file. One word per line. Lines starting with `#` and blank lines are ignored.

```text
# company-words.txt
Acme
AcmeCorp
acme-inc
ACME Holdings
```

### `--addresses "csv,of,tokens"`

Address fragments: city, street, ZIP, neighborhood. Whitespace-split.

```bash
--addresses "350 Fifth Avenue,New York,Manhattan,10118"
```

### `--custom <path>`

Free-form keywords — sports team, mascot, products, slogans, founder names, pet names if you've done OSINT. One per line.

```text
# custom.txt
falcons
project-zero
mascot
intranet
```

### `--usernames <path>`

One username per line. The generator emits per-user candidates anchored to each username.

```text
# users.txt
admin
helpdesk
svc_backup
jsmith
```

### `--names <path>`

`First Last [username]` per line, whitespace- or tab-separated.

```text
# people.txt - all three forms accepted
John Smith jsmith
Jane Doe j.doe
Mary Johnson
```

- **3 tokens** → first, last, **explicit username**.
- **2 tokens** → first, last. Usernames are **derived** in common schemes: `john`, `smith`, `jsmith`, `johns`, `john.smith`, `john_smith`, `johnsmith`. Each is emitted as a separate `username:password` line.
- **1 token** → treated as a first name only.

Accented input (`José García`, `Σπύρος Παπαδόπουλος`) is preserved AND ASCII-folded — `Jose`, `Garcia` — both variants feed the generator.

---

## Output files in detail

### `spray.txt`

One password per line. Most-likely-first. Suitable for any spray tool.

Sample with `--company-words "Acme" --complexity ulds`:

```text
Acme2026!
Acme2025!
Acme2024!
Acme2026#
Acme2026@
Acme1!
Acmecorp1!
Summer2026!
Winter2026!
Spring2026!
…
Password1!
Welcome1!
```

### `user_pass.txt`

`username:password` per line. Multiple lines per user (one for each candidate password). Format is identical to what tools like `hydra -C` expect.

Sample for an identity `John Smith jsmith`:

```text
jsmith:Jsmith1!
jsmith:Jsmith2026!
jsmith:John2026!
jsmith:Smith2026!
jsmith:John.smith1!
jsmith:Acme2026!      ← from --company-overlay
jsmith:Acme2025!
…
```

When `--names` has no explicit username column, every derived username variant gets its own block of lines:

```text
mjohnson:Mary2026!
maryj:Mary2026!
mary.johnson:Mary2026!
mary_johnson:Mary2026!
maryjohnson:Mary2026!
mary:Mary2026!
johnson:Mary2026!
```

Files are written with mode `0600` (owner-only) to avoid leaking generated lists on shared systems.

---


## Full flag reference

### Inputs

| Flag | Description |
|---|---|
| `--company-words CSV` | Comma-separated company-related words. |
| `--company-file PATH` | File with company words, one per line. |
| `--addresses CSV` | Comma-separated address / city / zip tokens. |
| `--usernames PATH` | File with usernames, one per line. |
| `--names PATH` | File with `First Last [username]` per line. |
| `--custom PATH` | File with custom keywords (hobbies, mascot, products). |

### Tuning

| Flag | Description | Default |
|---|---|---|
| `--years START-END` | Year range. Current year ranked first. | `cur-4..cur+1` |
| `--no-seasons` | Drop Winter / Spring / Summer / Fall / Autumn. | off |
| `--no-months` | Drop month-name patterns. | off |
| `--include-leet` | Add leet substitutions (`a→@`, `e→3`, `i→1`, `o→0`, `s→$`, `t→7`). | off |
| `--min-length N` | Minimum password length. | `8` |
| `--max-length N` | Maximum password length. | `64` |
| `--complexity STR` | Required classes. Combination of `u`/`l`/`d`/`s`, or `none`. | `none` |
| `--max-spray N` | Cap spray list at top-N. `0` = no cap. | `5000` |
| `--max-per-user N` | Cap per-identity candidates. | `100` |
| `--company-overlay N` | Top-N spray candidates appended per user. | `20` |

### Output

| Flag | Description |
|---|---|
| `--out-spray PATH` | Spray list output path. Default `spray.txt`. |
| `--out-user-pass PATH` | Per-user output path. Default `user_pass.txt`. |
| `--append` | Append to existing files instead of overwriting. |
| `-v`, `--verbose` | Show per-stage counts on stderr. |
| `-q`, `--quiet` | Suppress the final summary. |

### `--complexity` examples

| Value | Means |
|---|---|
| `none` | No filter (default). |
| `ul` | At least one upper AND one lower. |
| `uld` | Upper + lower + digit. |
| `ulds` | Upper + lower + digit + special. |
| `d` | Must contain at least one digit. |

---

## Recipes for common engagements

### 1. Pure spray, conservative (no lockouts)

Three-strikes lockout policy — keep the list tight, only the highest-confidence candidates.

```bash
./passpwn.py \
  --company-words "Acme,AcmeCorp" \
  --years 2024-2026 \
  --complexity ulds --min-length 8 \
  --max-spray 200 \
  --out-spray spray.txt
```

### 2. Targeted attack with full name list

You have full names but not usernames. Let `passpwn` derive the schemes.

```bash
./passpwn.py \
  --company-words "Acme" \
  --names people.txt \
  --custom keywords.txt \
  --complexity ulds \
  --max-per-user 30 \
  --out-user-pass user_pass.txt
```

### 3. No seasonal patterns (rotation-free org)

If you've confirmed the target doesn't force periodic resets, the seasonal stuff is just noise.

```bash
./passpwn.py \
  --company-words "Acme,Acme Holdings" \
  --names people.txt \
  --no-seasons --no-months \
  --complexity ulds \
  --out-spray spray.txt --out-user-pass user_pass.txt
```

### 4. Service-account brute force

Service accounts (`svc_backup`, `sql_admin`, `iis_app`) often have non-rotating passwords with simple patterns.

```bash
./passpwn.py \
  --company-words "Acme" \
  --usernames svc_accounts.txt \
  --complexity ul \
  --min-length 6 --max-length 14 \
  --max-per-user 200 \
  --out-user-pass svc_brute.txt
```

### 5. Maximum coverage (offline cracking)

You captured hashes, lockouts aren't a concern, throw everything.

```bash
./passpwn.py \
  --company-words "Acme,AcmeCorp,Inc,Holdings" \
  --addresses "New York,NYC,10001,Manhattan" \
  --names people.txt --usernames users.txt \
  --custom keywords.txt \
  --years 2018-2027 --include-leet \
  --max-spray 0 --max-per-user 1000 \
  --out-spray spray.txt --out-user-pass user_pass.txt
```
