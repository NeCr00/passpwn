# Passpwn - Password Wordlist Generator

**Passpwn** is a powerful and flexible Python CLI tool for generating customized password wordlists based on a configurable JSON template.

It is designed for:

* **Web Application Testing**: Form logins, APIs (Hydra, Burp Intruder, ffuf)
* **Service Brute Forcing**: SSH, RDP, SMTP (ncrack, Medusa)
* **Internal Assessments**: Targeted password lists based on company naming conventions, admin patterns, employee names, and password rotation schemes



## 🛠 How It Works

Passpwn automates the generation of passwords using patterns and rules you define in a configuration file:

1. **Load Config**
   Reads a `config.json` file which defines patterns, decorations, transformations, and constraints for password generation.

2. **Base Words**
   You provide a list of base words — typically company names, usernames, or admin keywords — via CLI or input file.

3. **Pattern Expansion**
   Passwords are constructed by combining placeholders such as `{year}`, `{season}`, `{quarter}`, `{special_chars}`, `{num_seq}` — based on your config.

4. **Leetspeak Transformations**
   Optionally applies configurable leetspeak substitutions (e.g., `a → @/4`) to generate even more variants.

5. **Policy & Length Filters**
   Optionally enforce password policy (uppercase, numbers, special characters), and filter by min/max password length.

6. **Deduplication & Output**
   The tool removes duplicates and outputs the final wordlist either to the terminal or to a file.



## ⚙️ Configuration JSON: How It Works

Your `config.json` defines the rules and patterns that drive the generation process. Each key in the config corresponds to a building block:

* `base_words`: defines the `{custom_word}` placeholder.
* `case_variants`: controls how case variants will be applied (lowercase, uppercase, title case).
* `separators`: defines possible separator characters to insert between parts when `{separators}` is used in patterns.
* `decorations`: defines common special characters and numeric sequences used in passwords.
* `seasons`, `quarters`: define lists of seasons and quarters for use in patterns.
* `patterns`: this is the heart of the config — patterns define how final passwords are built using placeholders.
* `transformations`: defines leetspeak mappings to apply when `--leet` is used.
* `policy_requirements`: defines which rules to enforce when `--enforce-policy` is enabled.

### Supported Placeholders

| Placeholder       | Meaning                                        |
| ----------------- | ---------------------------------------------- |
| `{custom_word}`   | Each base word you provide                     |
| `{word_lc}`       | Lowercase version of final password            |
| `{word_uc}`       | Uppercase version of final password            |
| `{word_tc}`       | Title Case version of final password           |
| `{year}`          | Current year and N-1 previous years            |
| `{quarter}`       | Q1, Q2, etc.                                   |
| `{season}`        | Seasonal terms (Spring, Summer, etc.)          |
| `{special_chars}` | Special characters defined in config           |
| `{num_seq}`       | Common numeric sequences defined in config     |
| `{separators}`    | Separators between parts (if used in patterns) |



## Example Configuration JSON

```json
{
  "base_words": ["{custom_word}"],
  "case_variants": ["{word_lc}", "{word_uc}", "{word_tc}"],
  "separators": ["", "-", "_", "."],
  "decorations": {
    "special_chars": ["!", "@", "#", "$", "%", "&", "*"],
    "num_seq": ["001", "007", "123", "321", "1"]
  },
  "seasons": ["Spring", "Summer", "Autumn", "Winter"],
  "quarters": ["Q1", "Q2", "Q3", "Q4", "q1", "q2"],
  "patterns": {
    "simple": [
      "{custom_word}",
      "{custom_word}{special_chars}",
      "{custom_word}{num_seq}",
      "{custom_word}{special_chars}{num_seq}",
      "{custom_word}{num_seq}{special_chars}",
      "{custom_word}{num_seq}",
      "{custom_word}{special_chars}{special_chars}"
    ],
    "year": [
      "{custom_word}{year}",
      "{custom_word}{year}{special_chars}",
      "{custom_word}{year}{num_seq}",
      "{custom_word}{year}{special_chars}{num_seq}",
      "{custom_word}{special_chars}{year}",
      "{custom_word}{num_seq}{year}",
      "{custom_word}{separators}{year}"
    ],
    "quarter": [
      "{custom_word}{quarter}",
      "{custom_word}{quarter}{year}",
      "{custom_word}{special_chars}{quarter}{year}",
      "{custom_word}{quarter}{special_chars}",
      "{custom_word}{quarter}{year}{special_chars}"
    ],
    "seasonal": [
      "{season}{year}{special_chars}",
      "{custom_word}{season}",
      "{custom_word}{season}{year}",
      "{custom_word}{season}{special_chars}",
      "{custom_word}{season}{special_chars}{num_seq}",
      "{custom_word}{season}{year}{special_chars}",
      "{custom_word}{special_chars}{season}{year}",
      "{custom_word}{separators}{season}{separators}{year}"
    ]
  },
  "transformations": {
    "a": ["@", "4"],
    "b": ["8"],
    "e": ["3"],
    "g": ["9", "6"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"]
  },
  "policy_requirements": ["uppercase", "number", "special"]
}
```

---

## 🚀 Installation & Setup

```bash
git clone https://github.com/your-org/generate-wordlist.git
cd generate-wordlist
```

## ⚡ Quick Start Example

```bash
python3 generate_wordlist.py \
  --config config.json \
  --words navarino,admin \
  --years 3 \
  --minlen 8 --maxlen 16 \
  --leet \
  --enforce-policy \
  --output passwords.txt
```

### Key Options:

* `--leet`: Enable full leetspeak transformation.
* `--enforce-policy`: Enforce policy requirements (uppercase, number, special).
* `--years N`: Include current and N-1 previous years in `{year}` placeholder.



## 🌟 Usage Examples

**Admin-focused list**

```bash
python3 generate_wordlist.py --words admin --leet --enforce-policy --output admin_pwds.txt
```

**Employee names from file, no leet**

```bash
python3 generate_wordlist.py --input employees.txt --years 1 --output employees_list.txt
```



## 💡 Tips & Best Practices

* Tune your `patterns`: Keep only those relevant for your target environment to avoid unnecessary combinations.
* Use smaller `--years` to reduce output size.
* Filter early: Apply `--minlen`, `--maxlen`, and `--enforce-policy` to produce cleaner results.
* Combine with known wordlists: You can merge Passpwn’s output with standard password lists for hybrid attacks.
* **Test the results**: Use in tools like Hydra, Ncrack, or Burp Suite.



