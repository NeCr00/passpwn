# Generate Wordlist Tool

A powerful Python CLI utility to craft highly customized password wordlists from a JSON configuration.

Ideal for:
- **Web App Testing**: Form logins, APIs (Hydra, Burp Intruder, ffuf)  
- **Service Brute Forcing**: SSH, RDP, SMTP (ncrack, Medusa)  
- **Internal Assessments**: Employee or product-named schemes


## 🧩 How It Works

1. **Load Config**  
   Read a JSON file that defines patterns, decorations, and leet transformations in order to generate the password list  
2. **Base Words**  
   Supply company names, admin keywords, or usernames. 
3. **Pattern Expansion**  
   Combine elements (years, seasons, quarters, special chars, numeric sequences) into template-based passwords.  
4. **Leet Transforms**  
   Optionally create all combinations of character substitutions (e.g., `a → @/4`). Leet configuration is done through .json config file  
5. **Policy & Length Filters**  
   Enforce uppercase, numbers, special chars. Also filter the passwords based on specific length
6. **Deduplicate & Output**  
   Preserve insertion order; output to stdout or file.


## 🔧 Configuration JSON Explained

How the JSON Works: This configuration file acts as a blueprint for the entire generation process. Each key corresponds to a specific building block:

- base_words: your starting tokens (company names, ‘admin’, or usernames) injected via {custom_word}.

- case_variants: declares how to alter letter casing ({word_lc}, {word_uc}, {word_tc}).

- separators, decorations, seasons, quarters, and patterns work in tandem to compose passwords by replacing placeholders like {year}, {season}, and {special_chars} with actual values, iterating through every possible combination.

- transformations defines letter→leet mappings; with --leet, the script exhaustively applies all substitution permutations for each character in every generated password.

- policy_requirements enforces complexity rules (uppercase, digit, special), pruning candidates that fail to meet your security policy.

Edit these arrays and objects to adapt the wordlist generator to any corporate naming convention or password rotation scheme.

Below is the base configuration json file which is used to define all the rules and patterns:

```jsonc
{
  "base_words": ["{custom_word}"],             //Base word -> User supplied words like company name, admin keywords, username, etc. 

  "case_variants": [                           //Type of password variants which will be included in the generation of the password list
    "{word_lc}",                               // lowercase passwords format (e.g., "admin")
    "{word_uc}",                               // uppercase passwords format (e.g., "ADMIN")
    "{word_tc}"                                // title case password formats (e.g., "Admin")
  ],

  "separators": ["", "-", "_", "."],      // Array<string>: joiners between segments. For instance {custom_word}{seperators}{year}

  "decorations": {                              // Object with two arrays:
    "special_chars": ["!","@","#","$","%","&","*"],  //Array of special characters used in the password list
    "num_seq":       ["001","007","123","321","1"]       // Array of common numeric sequences used in passwords
  },

  "seasons": ["Spring","Summer","Autumn","Winter"],  // Array<string>: seasonal markers
  "quarters": ["Q1","Q2","Q3","Q4","q1","q2"],                // Array<string>: fiscal quarters

// Patterns used to construct the passwords
  "patterns": {                                 //Definition of simple password patterns
    "simple":    [                               // e.g., "{custom_word}", "{custom_word}{special_chars}"...
      "{custom_word}",
      "{custom_word}{special_chars}",
      "{custom_word}{num_seq}",
      "{custom_word}{special_chars}{num_seq}",
      "{custom_word}{num_seq}{special_chars}",
      "{custom_word}{num_seq}",
      "{custom_word}{special_chars}{special_chars}"
    ],
    "year": [                                   // templates using {year}
      "{custom_word}{year}",
      "{custom_word}{year}{special_chars}",
      "{custom_word}{year}{num_seq}",
      "{custom_word}{year}{special_chars}{num_seq}",
      "{custom_word}{special_chars}{year}",
      "{custom_word}{num_seq}{year}"
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
      "{custom_word}{special_chars}{season}{year}"
    ]
  },

  "transformations": {                        // Object<string, Array<string>>: leet speak mappings
    "a": ["@","4"], "b": ["8"], "e": ["3"],
    "g": ["9","6"], "i": ["1","!"], "o": ["0"],
    "s": ["$","5"], "t": ["7"]
  },

  "policy_requirements": ["uppercase","number","special"] // Array<string>: enforceable checks
}
```
## Installation & Setup
```bash
git clone https://github.com/your-org/generate-wordlist.git
```
## Quick Start
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
    --leet: full combinatorial leet substitutions

    --enforce-policy: filter by uppercase, digits, special
## Usage Examples
**Admin-focused list**
```bash
python3 generate_wordlist.py --words admin --leet --enforce-policy --output admin_pwds.txt
```
**Employee names from file, no leet**
```bash
python3 generate_wordlist.py --input employees.txt --years 1 --output employees_list.txt
```

## Tips & Best Practices

- Tune patterns: remove unused sections to speed up generation.

- Limit years: fewer --years reduces combinatorial size.

- Filter early: use --minlen/--maxlen and --enforce-policy to prune.

- Combine wordlists: merge with common passwords for hybrid attacks.



