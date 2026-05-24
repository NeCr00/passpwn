<div align="center">

# `passpwn`

**Targeted password wordlists for authorized penetration tests.**

*Spray-ready and per-user lists, ranked by patterns observed in real-world breach data.*

</div>

---

## Quick start

```bash
chmod +x passpwn.py

./passpwn.py \
  --company-words "Acme,AcmeCorp" \
  --names people.txt \
  --complexity ulds \
  --out-spray spray.txt \
  --out-user-pass user_pass.txt
```

Standard library only. No `pip install`. Python 3.9+.

---

## What you get

| File | Format | Use it for |
|---|---|---|
| `spray.txt` | one password per line | password spraying across many users |
| `user_pass.txt` | `username:password` per line | targeted brute force per identity |

Both are sorted **most-likely-first**. The per-user list is written only when `--usernames` or `--names` is given.

---

## How it ranks

Top of the list is the **king pattern** — `Capitalize` + `Year` + `!` — anchored to *your* target's words.

```text
Acme2026!     ← #1 for company "Acme"
Acme2025!
Acme1!
Acmecorp2026!
Summer2026!
Winter2026!
…
Password1!    ← built-in fallbacks ranked last
```

Built from real password-breach research — the dominant `?u?l?l?l?l?l?d?d?s` mask, append-not-prepend complexity habits, seasonal rotation patterns, and the company-name effect (~20% of breached corporate passwords contain the company's name).

---

## Inputs

Pass any combination. Earlier sources are weighted higher.

- `--company-words`  &nbsp;—&nbsp; `"Acme,AcmeCorp,acme-inc"`
- `--addresses`  &nbsp;—&nbsp; `"350 Fifth Ave,New York,10118"`
- `--custom <file>`  &nbsp;—&nbsp; hobbies, mascot, sports team, product names
- `--names <file>`  &nbsp;—&nbsp; `First Last [username]` per line
- `--usernames <file>`  &nbsp;—&nbsp; one username per line

---

## Tuning

| Flag | Effect | Default |
|---|---|---|
| `--years 2022-2027` | Year range. Current year ranked first. | `cur-4..cur+1` |
| `--complexity ulds` | Require Upper / Lower / Digit / Special | none |
| `--min-length` / `--max-length` | Length filter | `8` / `64` |
| `--no-seasons` | Drop Winter / Spring / Summer / Fall / Autumn | off |
| `--no-months` | Drop month-name patterns | off |
| `--include-leet` | Add leet substitutions (`a→@`, `e→3`, …) | off |
| `--max-spray N` | Cap spray list at top-N | `5000` |
| `--max-per-user N` | Cap per-identity candidates | `100` |
| `--company-overlay N` | Top-N spray entries appended per user | `20` |
| `--append` | Append instead of overwrite | off |
| `-v` / `-q` | Verbose / quiet | summary |

Run `./passpwn.py --help` for the full reference.

---

## Examples

**Spray with AD complexity policy**

```bash
./passpwn.py --company-words "Acme,acme-corp" \
             --complexity ulds --min-length 8 \
             --max-spray 1000 --out-spray spray.txt
```

**Targeted, no seasonal noise**

```bash
./passpwn.py --company-words "Acme" \
             --names people.txt --custom keywords.txt \
             --no-seasons --no-months \
             --complexity ulds \
             --out-user-pass user_pass.txt
```

**Wide-net engagement**

```bash
./passpwn.py --company-words "Acme,AcmeCorp,Inc,Holdings" \
             --addresses "New York,NYC,10001" \
             --names people.txt --usernames svc_accounts.txt \
             --custom keywords.txt \
             --years 2020-2027 --include-leet \
             --max-spray 5000 --max-per-user 50 \
             --out-spray spray.txt --out-user-pass user_pass.txt
```

---

## Notes

- Output files written with mode `0600`.
- Offline. No network calls. No telemetry.
- Design spec: [`docs/superpowers/specs/2026-05-24-passpwn-design.md`](docs/superpowers/specs/2026-05-24-passpwn-design.md)

---

<div align="center">

**For authorized engagements only.**

</div>
