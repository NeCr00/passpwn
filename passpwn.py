#!/usr/bin/env python3
"""
passpwn - Targeted password wordlist generator for authorized pentests.

Builds two complementary wordlists:
  spray.txt      One password per line, ordered most-likely-first.
                 For password-spraying a single password across many users.
  user_pass.txt  username:password per line. For targeted brute force where
                 each account gets its own candidate set. Only written when
                 --usernames or --names is provided.

The generator encodes patterns observed in published breach research:
  * dominant mask  Capitalize + lowers + digits + symbol  (e.g. Summer18!)
  * append-not-prepend complexity habits
  * company-name + year + ! ("king" pattern)
  * seasonal/monthly rotation patterns

For authorized engagements only. No network calls. No telemetry.

Design spec: docs/superpowers/specs/2026-05-24-passpwn-design.md
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

# ---------------------------------------------------------------------------
# Constants - sourced from password breach research (see spec)
# ---------------------------------------------------------------------------

# Top base words appearing in breach corpora across industries.
GLOBAL_TOP_WORDS = [
    "password", "admin", "welcome", "letmein", "qwerty", "iloveyou",
    "monkey", "dragon", "passw0rd", "p@ssw0rd", "login", "master",
    "hello", "freedom", "whatever", "trustno1", "abc123", "starwars",
    "superman", "batman", "football", "baseball", "summer", "winter",
]

SEASONS = ["Winter", "Spring", "Summer", "Fall", "Autumn"]

MONTHS_FULL = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]
MONTHS_SHORT = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]

# Number tails ranked by observed frequency in breach data, most-common first.
NUMBER_TAILS = [
    "1", "123", "12", "1234", "12345", "01",
    "007", "69", "420", "111", "999", "00", "21", "22", "23",
]

# Symbol tails ranked by observed frequency in breach data, most-common first.
SYMBOL_TAILS = ["!", "!!", "@", "#", "$", "?", ".", "*"]

# Leetspeak substitutions.  Conservative subset that matches what cracking
# tools test first.
LEET_MAP = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"})

VALID_COMPLEXITY_CLASSES = set("ulds")

DEFAULT_MIN_LENGTH = 8
DEFAULT_MAX_LENGTH = 64
DEFAULT_MAX_SPRAY = 5000
DEFAULT_MAX_PER_USER = 100
DEFAULT_COMPANY_OVERLAY = 20


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def eprint(*args, **kwargs) -> None:
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def die(msg: str, code: int = 2) -> None:
    """Print a usage/error message and exit."""
    eprint(f"passpwn: error: {msg}")
    sys.exit(code)


def ascii_fold(s: str) -> str:
    """Strip accents/diacritics: 'José' -> 'Jose'."""
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def read_lines(path: str) -> list[str]:
    """Read a file as UTF-8 lines, replacing decode errors.  Strips trailing
    whitespace, drops empty / comment lines."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except FileNotFoundError:
        die(f"input file not found: {path}")
    except OSError as e:
        die(f"could not read {path}: {e}")
    lines = []
    for raw in data.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def split_tokens(s: str) -> list[str]:
    """Split on whitespace, dash, underscore.  Keep non-empty pieces."""
    return [p for p in re.split(r"[\s\-_]+", s) if p]


def has_required_classes(s: str, required: set[str]) -> bool:
    """True iff s contains at least one char from every required class."""
    if not required:
        return True
    if "u" in required and not any(c.isupper() for c in s):
        return False
    if "l" in required and not any(c.islower() for c in s):
        return False
    if "d" in required and not any(c.isdigit() for c in s):
        return False
    if "s" in required and not any((not c.isalnum()) and (not c.isspace()) for c in s):
        return False
    return True


# ---------------------------------------------------------------------------
# Stage 1 - base-word collection
# ---------------------------------------------------------------------------

def collect_base_words(
    company_words: list[str],
    addresses: list[str],
    custom: list[str],
    no_seasons: bool = False,
    no_months: bool = False,
) -> tuple[list[str], list[str]]:
    """Build the base-word lists.  Returns a tuple `(targeted, builtin)`:

      - `targeted`   - user-provided words (company / address / custom).
                       These are the highest-signal words for a targeted
                       attack against this org.
      - `builtin`    - global top-words from breach research.  Always tried
                       but ranked LOWER than targeted words.

    Order within each list determines insertion-order tie-breaking.

    When `no_seasons` or `no_months` is set, season/month tokens are stripped
    from the built-in global top words list (but NOT from user-provided
    inputs - if the operator explicitly passes 'Summer' as a company word,
    that's intentional and we keep it).
    """
    targeted: list[str] = []
    builtin: list[str] = []
    seen: set[str] = set()

    def add(lst: list[str], token: str) -> None:
        if not token:
            return
        key = token.lower()
        if key in seen:
            return
        seen.add(key)
        lst.append(key)

    # Company words first (highest signal).
    for raw in company_words:
        for piece in split_tokens(raw):
            add(targeted, piece)
        joined = "".join(split_tokens(raw))
        if joined:
            add(targeted, joined)

    # Address tokens (city, street name, zip, etc.).
    for raw in addresses:
        for piece in split_tokens(raw):
            add(targeted, piece)

    # Custom keywords (hobbies, mascot, sports team, ...).
    for raw in custom:
        for piece in split_tokens(raw):
            add(targeted, piece)
        joined = "".join(split_tokens(raw))
        if joined:
            add(targeted, joined)

    # Built-in global top words (always-include), filtered by --no-* flags.
    season_blocklist = {s.lower() for s in SEASONS} if no_seasons else set()
    month_blocklist = (
        {m.lower() for m in MONTHS_FULL} | {m.lower() for m in MONTHS_SHORT}
        if no_months else set()
    )
    for w in GLOBAL_TOP_WORDS:
        if w.lower() in season_blocklist or w.lower() in month_blocklist:
            continue
        add(builtin, w)

    return targeted, builtin


# ---------------------------------------------------------------------------
# Stage 3 - mutation engine.
#
# Each function below returns an *ordered* list of candidate strings.  The
# returned order IS the priority order (index 0 is the most likely guess).
# We pair them with priorities at the call site.
# ---------------------------------------------------------------------------

def mutations_for_word(
    word: str,
    years: list[int],
    no_seasons: bool,
    no_months: bool,
    include_leet: bool,
) -> list[str]:
    """Return ordered mutations of a single base word."""
    out: list[str] = []
    if not word:
        return out

    cap = word.capitalize()  # First letter upper, rest lower
    low = word.lower()
    up = word.upper()

    # ---- Tier 1: Capitalized + most-common suffixes (priority 0-N)
    out.append(cap)                     # Acme
    out.append(cap + "1")               # Acme1
    out.append(cap + "!")               # Acme!
    out.append(cap + "123")             # Acme123
    out.append(cap + "1!")              # Acme1!
    out.append(cap + "@1")              # Acme@1
    out.append(cap + "01")              # Acme01

    # Year suffixes (current year first; spec: --years lists current year first
    # when default).
    for y in years:
        out.append(f"{cap}{y}")          # Acme2026
    # Year + king symbol "!" (the dominant rotation pattern)
    for y in years:
        out.append(f"{cap}{y}!")         # Acme2026!
    # Year + other common symbols
    for y in years:
        for sym in ("#", "@", "$", "."):
            out.append(f"{cap}{y}{sym}")  # Acme2026#

    # 2-digit year variants (e.g. Acme26, Acme26!)
    for y in years:
        yy = f"{y:02d}"[-2:]
        out.append(f"{cap}{yy}")          # Acme26
        out.append(f"{cap}{yy}!")         # Acme26!

    # ---- Tier 2: Word + remaining number tails
    used = {"1", "123"}
    for n in NUMBER_TAILS:
        if n in used:
            continue
        out.append(cap + n)              # Acme12, Acme1234, ...

    # ---- Tier 3: Word + remaining symbol tails
    for s in SYMBOL_TAILS[1:]:           # skip "!" (already used)
        out.append(cap + s)              # Acme@, Acme#, ...

    # ---- Tier 4: case variants of the most useful patterns
    out.append(low)                      # acme
    out.append(up)                       # ACME
    out.append(low + "1")
    out.append(low + "123")
    out.append(low + "!")
    out.append(up + "1")
    out.append(up + "!")
    for y in years:
        out.append(f"{low}{y}")
        out.append(f"{up}{y}")
    for y in years:
        out.append(f"{low}{y}!")
        out.append(f"{up}{y}!")

    # ---- Tier 5: Word + @ + year (e.g. Acme@2025)
    for y in years:
        out.append(f"{cap}@{y}")

    # ---- Tier 6: Word + Season + year (anchored)
    if not no_seasons:
        for season in SEASONS:
            for y in years:
                out.append(f"{cap}{season}{y}")
                out.append(f"{cap}{season}{y}!")

    # ---- Tier 7: Word + Month + year (anchored)
    if not no_months:
        for month in MONTHS_FULL:
            for y in years:
                out.append(f"{cap}{month}{y}")
        for month in MONTHS_SHORT:
            for y in years:
                out.append(f"{cap}{month}{y}")

    # ---- Tier 8: Leetspeak (opt-in)
    if include_leet:
        leet_cap = cap.translate(LEET_MAP)
        leet_low = low.translate(LEET_MAP)
        if leet_cap != cap:
            out.append(leet_cap)
            out.append(leet_cap + "1!")
            out.append(leet_cap + "!")
            for y in years:
                out.append(f"{leet_cap}{y}!")
        if leet_low != low and leet_low != leet_cap:
            out.append(leet_low)
            out.append(leet_low + "1!")

    return out


def standalone_mutations(
    years: list[int],
    no_seasons: bool,
    no_months: bool,
) -> list[str]:
    """Mutations that aren't anchored to any base word.  Mostly seasonal /
    monthly patterns that work standalone (e.g. Summer2026!).  These are
    extremely common in environments enforcing periodic password rotation."""
    out: list[str] = []

    if not no_seasons:
        # Highest priority: Season + current-first-year + !
        for y in years:
            for season in SEASONS:
                out.append(f"{season}{y}!")
        for y in years:
            for season in SEASONS:
                out.append(f"{season}{y}")
        for y in years:
            for season in SEASONS:
                out.append(f"{season}{y}#")
        # 2-digit-year season variants
        for y in years:
            yy = f"{y:02d}"[-2:]
            for season in SEASONS:
                out.append(f"{season}{yy}!")
                out.append(f"{season}{yy}")

    if not no_months:
        for y in years:
            for month in MONTHS_FULL:
                out.append(f"{month}{y}!")
        for y in years:
            for month in MONTHS_FULL:
                out.append(f"{month}{y}")
        for y in years:
            for month in MONTHS_SHORT:
                out.append(f"{month}{y}!")

    # Bare years + bang are surprisingly common
    for y in years:
        out.append(f"{y}!")
        out.append(str(y))

    return out


# ---------------------------------------------------------------------------
# Stage 4 - filtering
# ---------------------------------------------------------------------------

def passes_filters(s: str, min_len: int, max_len: int, complexity: set[str]) -> bool:
    if len(s) < min_len or len(s) > max_len:
        return False
    if complexity and not has_required_classes(s, complexity):
        return False
    return True


# ---------------------------------------------------------------------------
# Ordered-dedup helper
# ---------------------------------------------------------------------------

class PriorityCollector:
    """Collects (candidate, priority) pairs, keeps the BEST (lowest) priority
    seen per candidate, and produces a flat list ordered by priority then by
    insertion order (stable)."""

    def __init__(self) -> None:
        self._best: dict[str, tuple[int, int]] = {}  # cand -> (priority, ins)
        self._next_ins = 0

    def add(self, candidate: str, priority: int) -> None:
        existing = self._best.get(candidate)
        if existing is None or priority < existing[0]:
            self._best[candidate] = (priority, self._next_ins)
        self._next_ins += 1

    def add_many(self, items: Iterable[str], base_priority: int = 0) -> None:
        for i, cand in enumerate(items):
            self.add(cand, base_priority + i)

    def ordered(self) -> list[str]:
        # Sort by (priority, insertion-index).  Stable.
        return [
            c for c, _ in sorted(
                self._best.items(),
                key=lambda kv: (kv[1][0], kv[1][1]),
            )
        ]

    def __len__(self) -> int:
        return len(self._best)


# ---------------------------------------------------------------------------
# Identity parsing
# ---------------------------------------------------------------------------

class Identity:
    __slots__ = ("first", "last", "usernames")

    def __init__(self, first: str, last: str, usernames: list[str]) -> None:
        self.first = first
        self.last = last
        # Always at least one entry; could be a list when we derive multiples.
        self.usernames = usernames

    def __repr__(self) -> str:
        return f"Identity(first={self.first!r}, last={self.last!r}, usernames={self.usernames!r})"


def derive_usernames(first: str, last: str) -> list[str]:
    """Generate common corporate username schemes from a first/last pair."""
    f = first.lower()
    l = last.lower()
    if not f and not l:
        return []
    out: list[str] = []
    def add(u: str) -> None:
        if u and u not in out:
            out.append(u)
    if f and l:
        add(f[0] + l)             # jsmith
        add(f + l[0])             # johns
        add(f + "." + l)          # john.smith
        add(f + "_" + l)          # john_smith
        add(f + l)                # johnsmith
    if f:
        add(f)
    if l:
        add(l)
    return out


def parse_identities(
    usernames_path: str | None,
    names_path: str | None,
) -> list[Identity]:
    """Parse --usernames and/or --names files into a deduplicated list of
    Identity objects."""
    identities: list[Identity] = []
    seen_keys: set[str] = set()

    def push(first: str, last: str, usernames: list[str]) -> None:
        key = (first.lower(), last.lower(), tuple(u.lower() for u in usernames))
        if key in seen_keys:
            return
        seen_keys.add(key)
        identities.append(Identity(first, last, usernames))

    if usernames_path:
        for u in read_lines(usernames_path):
            push("", "", [u])

    if names_path:
        for line in read_lines(names_path):
            parts = line.split()
            if not parts:
                continue
            if len(parts) == 1:
                # treat the single token as a first name; derive usernames
                first = parts[0]
                push(first, "", derive_usernames(first, ""))
            elif len(parts) == 2:
                # First Last - derive usernames since no explicit one
                first, last = parts
                push(first, last, derive_usernames(first, last))
            else:
                # First Last [middle...] username  -> last token is username
                # but we treat all middle tokens as part of last name to be
                # safe.  Common case is "First Last username" (3 tokens).
                first = parts[0]
                username = parts[-1]
                last = " ".join(parts[1:-1])
                # If the supposed username looks like a name word, fall back
                # to derived usernames (heuristic: usernames typically
                # lowercase with no whitespace and contain a digit, dot,
                # underscore, or are <= 12 chars without uppercase).
                push(first, last, [username])

    return identities


def identity_base_words(ident: Identity) -> list[str]:
    """Build per-identity base words, ordered by signal strength."""
    bases: list[str] = []
    seen: set[str] = set()

    def add(t: str) -> None:
        if not t:
            return
        k = t.lower()
        if k in seen:
            return
        seen.add(k)
        bases.append(k)

    first = ident.first.strip()
    last = ident.last.strip()
    usernames = [u.strip() for u in ident.usernames if u.strip()]

    # ASCII-folded variants for accented input
    first_fold = ascii_fold(first)
    last_fold = ascii_fold(last)

    # Username(s) first - highest signal for credential reuse
    for u in usernames:
        add(u)
        # Also the username with separators stripped
        joined = re.sub(r"[\W_]+", "", u)
        if joined:
            add(joined)

    if first:
        add(first)
        if first_fold and first_fold != first:
            add(first_fold)
    if last:
        add(last)
        if last_fold and last_fold != last:
            add(last_fold)

    # Combined first+last forms
    if first and last:
        add(first + last)
        add(first + "." + last)
        add(first + "_" + last)
        add(last + first)

    # Initials
    if first:
        add(first[0])
    if first and last:
        add(first[0] + last[0])
        add(first[0] + last)
        add(first + last[0])

    return bases


# ---------------------------------------------------------------------------
# Generation - spray list
# ---------------------------------------------------------------------------

# Priority bands.  Lower number = earlier in output = more likely.
#   Targeted words occupy 0 - TARGETED_BAND_SIZE.
#   Standalone season/month patterns sit between targeted and builtin.
#   Builtin words occupy BUILTIN_BASE upward.
# Choosing the bands so the dominant company patterns (Acme1, Acme!, ...,
# Acme2026!) all land before the strongest built-in patterns (Password,
# P@ssw0rd, ...).
TARGETED_BAND_SIZE = 100_000
STANDALONE_BASE = 200_000
BUILTIN_BASE = 300_000


def _emit_word_mutations(
    pc: "PriorityCollector",
    words: list[str],
    base_priority: int,
    years: list[int],
    no_seasons: bool,
    no_months: bool,
    include_leet: bool,
) -> None:
    """For each word, emit its mutations with a priority that interleaves the
    Nth mutation of every word together (so the top mutation of each word
    appears before the second mutation of any word in the same group)."""
    if not words:
        return
    span = len(words) + 1
    for word_idx, word in enumerate(words):
        for mut_idx, cand in enumerate(
            mutations_for_word(word, years, no_seasons, no_months, include_leet)
        ):
            priority = base_priority + mut_idx * span + word_idx
            pc.add(cand, priority)


def generate_spray(
    targeted_words: list[str],
    builtin_words: list[str],
    years: list[int],
    no_seasons: bool,
    no_months: bool,
    include_leet: bool,
    min_len: int,
    max_len: int,
    complexity: set[str],
    max_spray: int | None,
) -> list[str]:
    """Build the spray-list candidate set, sorted most-likely-first.

    Priority layout:
      targeted-word mutations  (0 .. TARGETED_BAND_SIZE-1)
      standalone season/month  (STANDALONE_BASE ..)
      built-in top-word mutations  (BUILTIN_BASE ..)
    """
    pc = PriorityCollector()

    # Targeted words first - these are the highest-signal guesses for this
    # specific engagement.
    _emit_word_mutations(
        pc, targeted_words, base_priority=0,
        years=years, no_seasons=no_seasons, no_months=no_months,
        include_leet=include_leet,
    )

    # Standalone Season/Month/Year patterns (anchored to nothing).  These
    # work universally for any environment with forced rotation.
    for i, c in enumerate(standalone_mutations(years, no_seasons, no_months)):
        pc.add(c, STANDALONE_BASE + i)

    # Built-in global top words - last-resort generics.
    _emit_word_mutations(
        pc, builtin_words, base_priority=BUILTIN_BASE,
        years=years, no_seasons=no_seasons, no_months=no_months,
        include_leet=include_leet,
    )

    ordered = pc.ordered()

    # Filter
    filtered: list[str] = []
    for c in ordered:
        if passes_filters(c, min_len, max_len, complexity):
            filtered.append(c)
        if max_spray is not None and len(filtered) >= max_spray:
            break
    return filtered


# ---------------------------------------------------------------------------
# Generation - per-user list
# ---------------------------------------------------------------------------

def generate_per_user(
    identities: list[Identity],
    years: list[int],
    no_seasons: bool,
    no_months: bool,
    include_leet: bool,
    min_len: int,
    max_len: int,
    complexity: set[str],
    max_per_user: int,
    overlay_top: list[str],
) -> list[tuple[str, str]]:
    """Return a flat list of (username, password) pairs for every identity.

    Each identity gets up to `max_per_user` distinct candidate passwords.
    For every accepted password, one line per derived username is emitted.

    Priority layout per identity:
      identity-anchored mutations (0 .. TARGETED_BAND_SIZE)
      company-wide overlay candidates (BUILTIN_BASE+)
    """
    out: list[tuple[str, str]] = []

    for ident in identities:
        bases = identity_base_words(ident)
        if not bases:
            continue

        pc = PriorityCollector()

        _emit_word_mutations(
            pc, bases, base_priority=0,
            years=years, no_seasons=no_seasons, no_months=no_months,
            include_leet=include_leet,
        )

        # Overlay: top company-wide candidates also tried for this user.
        for i, cand in enumerate(overlay_top):
            pc.add(cand, BUILTIN_BASE + i)

        ordered = pc.ordered()

        emitted = 0
        for cand in ordered:
            if not passes_filters(cand, min_len, max_len, complexity):
                continue
            for u in ident.usernames:
                out.append((u, cand))
            emitted += 1
            if emitted >= max_per_user:
                break

    return out


# ---------------------------------------------------------------------------
# Year parsing
# ---------------------------------------------------------------------------

def parse_years(arg: str | None, today: datetime | None = None) -> list[int]:
    """Parse --years argument like '2020-2026' into a list of ints, with
    the most-likely year (current year) first, then current+1, then descending
    past years."""
    if today is None:
        today = datetime.now()
    cur = today.year

    if arg is None:
        start = cur - 4
        end = cur + 1
    else:
        m = re.match(r"^\s*(\d{4})\s*-\s*(\d{4})\s*$", arg)
        if not m:
            die(f"invalid --years value {arg!r}; expected START-END like 2020-2026")
        start = int(m.group(1))
        end = int(m.group(2))
        if start > end:
            die(f"invalid --years range: start {start} is after end {end}")
        if end - start > 50:
            die(f"--years range too wide ({end - start + 1} years); cap at 50")

    all_years = list(range(start, end + 1))
    if not all_years:
        die("--years range produced no years")

    # Order: current year, then current+1, then descending past years, then
    # any remaining future years.  This puts the highest-signal years at the
    # top of the priority list.
    ordered: list[int] = []
    if cur in all_years:
        ordered.append(cur)
    if (cur + 1) in all_years:
        ordered.append(cur + 1)
    for y in sorted(all_years, reverse=True):
        if y not in ordered and y <= cur:
            ordered.append(y)
    for y in sorted(all_years):
        if y not in ordered:
            ordered.append(y)
    return ordered


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="passpwn",
        description=(
            "Generate targeted password wordlists for authorized penetration "
            "tests.  Produces a spray list and (when usernames are provided) "
            "a per-user username:password list."
        ),
        epilog=(
            "Examples:\n"
            "  passpwn.py --company-words acme,acmecorp --out-spray spray.txt\n"
            "  passpwn.py --company-words acme --names people.txt \\\n"
            "             --years 2020-2026 --complexity ulds\n"
            "  passpwn.py --usernames users.txt --custom keywords.txt \\\n"
            "             --no-months --max-spray 2000\n"
            "\n"
            "FOR AUTHORIZED ENGAGEMENTS ONLY.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    g = p.add_argument_group("input (at least one source required)")
    g.add_argument("--company-words", default="",
                   help="Comma-separated company-related words (name, short "
                        "name, ticker, products).")
    g.add_argument("--company-file", default=None,
                   help="File with company words, one per line.")
    g.add_argument("--addresses", default="",
                   help="Comma-separated address / city / zip tokens.")
    g.add_argument("--usernames", default=None,
                   help="File with usernames, one per line.")
    g.add_argument("--names", default=None,
                   help="File with 'First Last [username]' per line.")
    g.add_argument("--custom", default=None,
                   help="File with custom keywords (hobbies, mascot, etc.), "
                        "one per line.")

    g = p.add_argument_group("tuning")
    g.add_argument("--years", default=None,
                   help="Year range, e.g. 2020-2026.  Default: current_year-4"
                        " .. current_year+1.")
    g.add_argument("--no-seasons", action="store_true",
                   help="Skip Winter/Spring/Summer/Fall/Autumn patterns.")
    g.add_argument("--no-months", action="store_true",
                   help="Skip month-name patterns.")
    g.add_argument("--include-leet", action="store_true",
                   help="Include leetspeak substitutions (off by default).")
    g.add_argument("--min-length", type=int, default=DEFAULT_MIN_LENGTH,
                   help=f"Minimum password length (default {DEFAULT_MIN_LENGTH}).")
    g.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH,
                   help=f"Maximum password length (default {DEFAULT_MAX_LENGTH}).")
    g.add_argument("--complexity", default="none",
                   help="Required character classes; any combination of "
                        "u/l/d/s, or 'none'.  E.g. 'ulds' requires all four "
                        "classes.  (default: none)")
    g.add_argument("--max-spray", type=int, default=DEFAULT_MAX_SPRAY,
                   help=f"Cap spray list at top-N (default {DEFAULT_MAX_SPRAY}). "
                        "Use 0 for no cap.")
    g.add_argument("--max-per-user", type=int, default=DEFAULT_MAX_PER_USER,
                   help=f"Cap per-user list at N passwords per identity "
                        f"(default {DEFAULT_MAX_PER_USER}).")
    g.add_argument("--company-overlay", type=int, default=DEFAULT_COMPANY_OVERLAY,
                   help=f"Top-N spray candidates appended to every per-user "
                        f"identity (default {DEFAULT_COMPANY_OVERLAY}).")

    g = p.add_argument_group("output")
    g.add_argument("--out-spray", default="spray.txt",
                   help="Spray list output path (default spray.txt).")
    g.add_argument("--out-user-pass", default="user_pass.txt",
                   help="Per-user output path (default user_pass.txt).")
    g.add_argument("--append", action="store_true",
                   help="Append to existing output files instead of overwriting.")
    g.add_argument("--verbose", "-v", action="store_true",
                   help="Show per-stage counts on stderr.")
    g.add_argument("--quiet", "-q", action="store_true",
                   help="Suppress the final summary.")

    return p


def normalize_complexity(value: str) -> set[str]:
    v = value.strip().lower()
    if v in ("none", "", "any"):
        return set()
    bad = set(v) - VALID_COMPLEXITY_CLASSES
    if bad:
        die(f"invalid --complexity value {value!r}: unknown class(es) "
            f"{','.join(sorted(bad))}; accepted: u, l, d, s, or 'none'")
    return set(v)


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------

def write_lines(path: str, lines: Iterable[str], append: bool) -> int:
    mode = "a" if append else "w"
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    count = 0
    try:
        with os.fdopen(fd, mode, encoding="utf-8", newline="\n") as fh:
            for line in lines:
                fh.write(line)
                fh.write("\n")
                count += 1
    except OSError as e:
        die(f"could not write {path}: {e}")
    # Make sure perms are right even if file pre-existed.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return count


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    started = time.monotonic()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # ---- Validation
    if args.min_length < 1:
        die("--min-length must be >= 1")
    if args.max_length < args.min_length:
        die(f"--max-length ({args.max_length}) must be >= --min-length "
            f"({args.min_length})")
    if args.max_spray < 0:
        die("--max-spray must be >= 0")
    if args.max_per_user < 1:
        die("--max-per-user must be >= 1")
    if args.company_overlay < 0:
        die("--company-overlay must be >= 0")

    complexity = normalize_complexity(args.complexity)
    years = parse_years(args.years)

    # ---- Inputs
    company_words = [w for w in (s.strip() for s in args.company_words.split(",")) if w]
    if args.company_file:
        company_words.extend(read_lines(args.company_file))

    addresses = [w for w in (s.strip() for s in args.addresses.split(",")) if w]

    custom = read_lines(args.custom) if args.custom else []

    have_per_user = bool(args.usernames or args.names)
    have_any_input = bool(company_words or addresses or custom or have_per_user)
    if not have_any_input:
        parser.print_usage(sys.stderr)
        die("at least one input source is required "
            "(--company-words / --company-file / --addresses / --usernames / "
            "--names / --custom)")

    # ---- Stage 1: base words for the spray list
    targeted_words, builtin_words = collect_base_words(
        company_words, addresses, custom,
        no_seasons=args.no_seasons, no_months=args.no_months,
    )

    if args.verbose:
        eprint(f"[passpwn] targeted base words: {len(targeted_words)}")
        eprint(f"[passpwn] built-in top words: {len(builtin_words)}")
        eprint(f"[passpwn] years: {years}")
        eprint(f"[passpwn] complexity required classes: "
               f"{''.join(sorted(complexity)) or 'none'}")

    # ---- Spray list
    max_spray = args.max_spray if args.max_spray > 0 else None
    spray = generate_spray(
        targeted_words, builtin_words, years,
        args.no_seasons, args.no_months, args.include_leet,
        args.min_length, args.max_length, complexity,
        max_spray,
    )

    if args.verbose:
        eprint(f"[passpwn] spray candidates after filter: {len(spray)}")

    spray_written = write_lines(args.out_spray, spray, args.append)

    # ---- Per-user list
    user_pass_written = 0
    n_identities = 0
    if have_per_user:
        identities = parse_identities(args.usernames, args.names)
        n_identities = len(identities)

        if args.verbose:
            eprint(f"[passpwn] identities: {n_identities}")

        overlay = spray[: args.company_overlay] if args.company_overlay > 0 else []

        pairs = generate_per_user(
            identities, years,
            args.no_seasons, args.no_months, args.include_leet,
            args.min_length, args.max_length, complexity,
            args.max_per_user, overlay,
        )

        # Format as "username:password"
        lines = (f"{u}:{p}" for u, p in pairs)
        user_pass_written = write_lines(args.out_user_pass, lines, args.append)

    else:
        if args.verbose:
            eprint("[passpwn] no --usernames or --names provided; "
                   "skipping per-user list")

    # ---- Summary
    if not args.quiet:
        elapsed = time.monotonic() - started
        eprint(f"[passpwn] spray output:    {spray_written:>8d} lines -> "
               f"{args.out_spray}")
        if have_per_user:
            eprint(f"[passpwn] user_pass output: {user_pass_written:>8d} lines -> "
                   f"{args.out_user_pass}  ({n_identities} identities)")
        else:
            eprint(f"[passpwn] user_pass output: skipped (no --usernames/--names)")
        eprint(f"[passpwn] elapsed: {elapsed:.2f}s")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        eprint("\n[passpwn] interrupted")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - safety net
        import traceback
        traceback.print_exc()
        eprint(f"[passpwn] unexpected error: {exc}")
        sys.exit(1)
