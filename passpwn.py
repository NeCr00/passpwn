import argparse
import json
import logging
import sys
import re
import itertools
from pathlib import Path
from datetime import datetime
from collections import OrderedDict

# Setup logging
default_format = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt=default_format
)
logger = logging.getLogger(__name__)


def load_config(path: Path) -> dict:
    """Load and validate JSON config structure."""
    try:
        conf = json.loads(path.read_text(encoding='utf-8'))
    except Exception as e:
        logger.error("Error reading config %s: %s", path, e)
        sys.exit(1)

    required = [
        'base_words', 'case_variants', 'separators',
        'decorations', 'seasons', 'quarters', 'patterns',
        'transformations', 'policy_requirements'
    ]
    for key in required:
        if key not in conf:
            logger.error("Config missing required key: %s", key)
            sys.exit(1)
    return conf


def apply_leets(word: str, transforms: dict, exhaustive: bool) -> set:
    """Generate leetspeak variants, one substitution per char (iterative if exhaustive)."""
    variants = {word}
    for base in list(variants):
        for i, c in enumerate(base):
            if c.lower() in transforms:
                for sub in transforms[c.lower()]:
                    variants.add(base[:i] + sub + base[i+1:])
    if exhaustive:
        seen = set(variants)
        frontier = set(variants)
        while frontier:
            next_front = set()
            for w in frontier:
                for i, c in enumerate(w):
                    if c.lower() in transforms:
                        for sub in transforms[c.lower()]:
                            nw = w[:i] + sub + w[i+1:]
                            if nw not in seen:
                                seen.add(nw)
                                next_front.add(nw)
            frontier = next_front
            variants |= frontier
    return variants


def enforce_policy(pw: str, policies: list) -> bool:
    """Check password against uppercase/number/special requirements."""
    checks = {
        'uppercase': r'[A-Z]',
        'number':    r'\d',
        'special':   r'[^A-Za-z0-9]'
    }
    for p in policies:
        if p in checks and not re.search(checks[p], pw):
            return False
    return True


def expand_pattern(template: str, replacements: dict) -> list:
    """Expand a single pattern template into all placeholder combinations."""
    slots = re.findall(r"\{(.*?)\}", template)
    pools = []
    for slot in slots:
        if slot == 'separators':
            pools.append(replacements['separators'])
        elif slot in replacements:
            pools.append(replacements[slot])
        else:
            logger.error("Unknown placeholder in pattern: %s", slot)
            sys.exit(1)

    results = []

    # Normal expansion first
    for combo in itertools.product(*pools):
        result = template
        for slot, val in zip(slots, combo):
            if slot == 'separators':
                # Defer handling of separators → we will handle it below
                result = result.replace(f"{{{slot}}}", "{_SEP_}", 1)
            else:
                result = result.replace(f"{{{slot}}}", str(val), 1)

        # If separators were present, produce one result per separator
        if '{_SEP_}' in result:
            for sep in replacements['separators']:
                results.append(result.replace('{_SEP_}', sep))
        else:
            results.append(result)

    return results



def apply_case_variants(password: str, case_templates: list) -> set:
    """Apply case variants (lower, upper, title) to any password."""
    variants = set()
    for ct in case_templates:
        if ct == '{word_lc}':
            variants.add(password.lower())
        elif ct == '{word_uc}':
            variants.add(password.upper())
        elif ct == '{word_tc}':
            parts = re.split(r'([^A-Za-z0-9])', password)
            titled = ''.join(p.title() if re.match(r'\w+', p) else p for p in parts)
            variants.add(titled)
    return variants


def main():
    parser = argparse.ArgumentParser(
        description="Generate a password wordlist from a JSON config."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--words', '-w', help="Comma-separated base words")
    group.add_argument('--input', '-i', type=Path, help="File with one base word per line")
    parser.add_argument('--config', '-c', type=Path, required=True, help="JSON config file")
    parser.add_argument('--output', '-o', type=Path, help="Write passwords to this file")
    parser.add_argument('--minlen', type=int, default=0, help="Discard passwords shorter than this")
    parser.add_argument('--maxlen', type=int, default=0, help="Discard passwords longer than this (0=no limit)")
    parser.add_argument('--years', '-y', type=int, default=2, help="Include current + N-1 previous years")
    parser.add_argument('--leet', action='store_true', help="Apply leetspeak variants (exhaustive)")
    parser.add_argument('--enforce-policy', action='store_true', help="Filter by policy requirements in config")
    args = parser.parse_args()

    cfg = load_config(args.config)

    # Load base words
    if args.words:
        base_words = [w.strip() for w in args.words.split(',') if w.strip()]
    else:
        try:
            base_words = [l.strip() for l in args.input.read_text().splitlines() if l.strip()]
        except Exception as e:
            logger.error("Error reading input %s: %s", args.input, e)
            sys.exit(1)

    base_words = list(OrderedDict.fromkeys(base_words))

    # Prepare placeholder pools
    now = datetime.now()
    replacements = {
        'custom_word': base_words,  # will be overridden per iteration
        'year': [str(now.year - i) for i in range(args.years)],
        'quarter': cfg['quarters'],
        'season': cfg['seasons'],
        'special_chars': cfg['decorations']['special_chars'],
        'num_seq': cfg['decorations']['num_seq'],
        'separators': cfg['separators']

    }
    case_templates = cfg['case_variants']
    patterns = cfg['patterns']
    transforms = cfg['transformations']
    policies = cfg['policy_requirements']

    # 1) Expand patterns with raw placeholders
    raw_passwords = []
    for word in base_words:
        replacements['custom_word'] = [word]
        for tpl_list in patterns.values():
            for tpl in tpl_list:
                raw_passwords.extend(expand_pattern(tpl, replacements))

    # Deduplicate
    raw_unique = list(OrderedDict.fromkeys(raw_passwords))

    # 2) Apply case variants across all raw passwords
    case_applied = []
    for pw in raw_unique:
        case_applied.extend(apply_case_variants(pw, case_templates))

    case_unique = list(OrderedDict.fromkeys(case_applied))

    # 3) Leet, policy, length filters
    final_list = []
    for pw in case_unique:
        candidates = {pw}
        if args.leet:
            candidates |= apply_leets(pw, transforms, exhaustive=True)
        for cand in candidates:
            if len(cand) < args.minlen:
                continue
            if args.maxlen and len(cand) > args.maxlen:
                continue
            if args.enforce_policy and not enforce_policy(cand, policies):
                continue
            final_list.append(cand)

    # 4) Output
    out_f = open(args.output, 'w') if args.output else None
    for p in final_list:
        print(p)
        if out_f:
            out_f.write(p + '\n')
    if out_f:
        out_f.close()
        logger.info("Wrote %d passwords to %s", len(final_list), args.output)


if __name__ == '__main__':
    main()
