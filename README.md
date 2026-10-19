# SecurePass — Privacy-First Password Strength Checker

> **Cybersecurity Internship Project — Task 1**  
> A client-side, zero-telemetry password auditing tool built using pure **Python**, **JavaScript**, **Math / Regex**, and **Common Password Dictionary Lists**. Evaluates credentials using Shannon information entropy, brute-force search space models, dictionary unmasking, and adversarial hybrid mask detection.

---

## 1. Approved Technology Stack

Per the project requirements, this application strictly uses:

| Component | Technology | Role & Purpose |
| :--- | :--- | :--- |
| **Frontend UI** | **HTML5 & CSS3** | Clean, responsive developer interface featuring a circular radial score gauge. |
| **Client Engine** | **Vanilla JavaScript (ES6+)** | 100% client-side auditing, DOM control, and volatile in-memory processing. |
| **CLI Engine** | **Python 3 (Standard Library)** | Terminal interface using `getpass` (silent hidden input, zero echo, zero logging). |
| **Mathematical Logic** | **Math (`log2`, Shannon Entropy)** | Calculates empirical entropy ($H$) and character pool capacity ($E_{\text{pool}}$). |
| **Pattern Recognition** | **Regular Expressions (Regex)** | Detects leetspeak substitutions, repeated sequences, and targeted hybrid masks. |
| **Adversarial Dictionaries** | **SecLists Common Passwords** | Bundled offline wordlists (`wordlist.js` for JS, `common_passwords.txt` for Python). |

> **Privacy & Air-Gap Guarantee:** No external frameworks, no Node packages, no databases, no external APIs, and no telemetry. Passwords never leave local device memory.

---

## 2. Clean Project Structure

```text
task 1/
├── index.html                   # 1-Click Web Application (Double-click to run in any browser)
├── password_checker.py          # Python Terminal CLI Tool (python password_checker.py)
├── test_runner.py               # Automated Python Test Suite Runner (34 tests)
├── README.md                    # Technical documentation & security architecture
│
├── css/
│   └── styles.css               # Clean developer theme & circular progress ring styles
│
├── js/
│   ├── script.js                # Core JS strength analyzer, Shannon math & regex heuristics
│   └── wordlist.js              # SecLists 10,000 common passwords dictionary list
│
├── checker/                     # Modular Python Core Package
│   ├── __init__.py              # Package exports (analyze, StrengthResult)
│   ├── analyzer.py              # Python scoring engine & defensive recommendations
│   ├── entropy.py               # Shannon & pool search space calculations
│   ├── patterns.py              # Regex heuristics (leetspeak, walks, hybrid masks)
│   └── common_passwords.txt     # Offline common passwords dictionary file
│
└── tests/                       # Automated Verification Suites
    ├── test_javascript.js       # 31 Node.js cryptographic & privacy unit tests
    └── test_python.py           # 34 Python unit tests verifying detection & privacy
```

---

## 3. Direct 1-Click UI Execution

To open and use the interactive web application:

1. **One-Click Launch**: Simply **double-click** `index.html` in your Windows File Explorer (or run `start index.html` in your terminal).
2. Opens directly in your default web browser (Edge, Chrome, Firefox) with **zero setup required** (no npm, no server, 100% offline).

```bash
start index.html        # Windows
open index.html         # macOS
xdg-open index.html     # Linux
```
- **Live Real-Time Audit**: No "Analyze" button required. The circular SVG gauge and diagnostic checklist update immediately as you type.
- **Create Strong Password with Info Collection**:
  - **4-Word Passphrase (NIST SP 800-63B)**: Configurable word counts, separators, and cryptographic salts.
  - **Random Complex Characters**: Configurable length (12–32) and full character set customization.
  - **Collect Info & Defend (Memory Cue Hardener)**: Collects personal cues (word, name, memorable year/number), demonstrates why naive combinations (`coffee@2024`) fail against Hashcat mask attacks in &lt;0.1s, and cryptographically hardens them with CSPRNG dictionary words or salts to achieve &gt;80 bits of mathematical entropy.
- **1-Click Integration**: "Test in Strength Checker &rarr;" transfers any generated password directly into the audit tab for instant verification.

---


<img width="1471" height="729" alt="image" src="https://github.com/user-attachments/assets/532033f8-2eb4-4d02-851e-ab9950d0d8e1" /> <br><br><br>
<img width="1454" height="726" alt="image" src="https://github.com/user-attachments/assets/2fcf17d0-fbb1-47e7-95db-2845dfdd607c" />



## 4. How to Run the Python CLI

For a terminal-based security audit with silent credential input:

```bash
python password_checker.py
```

- Passwords are typed invisibly using Python's standard `getpass` module (zero screen echo).
- Analysis executes in memory, prints a formatted audit report, and immediately frees all memory references.

---

## 5. Cryptographic & Mathematical Foundation

### A. Shannon Character Entropy
Shannon entropy measures information density and randomness across characters:

$$\Large H = -\sum_{i=1}^{k} p_i \log_2(p_i)$$

Where:
- $k$ is the count of unique characters in the password.
- $p_i = \frac{\text{count}(c_i)}{L}$ is the empirical probability of character $c_i$.
- $L$ is the total length of the password.

**Total Shannon Entropy (in bits):**
$$\Large E_{\text{shannon}} = H \times L$$

- **Why it stops naive meters:** A repeated string like `aaaaaaaa` has $p_a = 1.0$ and $\log_2(1) = 0$, giving $H = 0\text{ bits}$ regardless of length.

### B. Theoretical Character Pool Entropy
Assuming each character is chosen uniformly at random from an alphabet of size $R$:

$$\Large E_{\text{pool}} = L \times \log_2(R)$$

Pool sizes by character class:
- Lowercase (`a-z`): 26
- Uppercase (`A-Z`): 26
- Digits (`0-9`): 10
- Symbols & Punctuation: 33 (Total printable pool = 95)

### C. Effective Entropy
$$\Large E_{\text{eff}} = \min(E_{\text{pool}}, E_{\text{shannon}})$$

Taking the conservative minimum prevents the tool from over-crediting long repetitive strings while still honoring alphabet variety.

---

## 6. Scoring & Penalty System

SecurePass uses a deterministic 0 to 100 scoring model:

### Score Composition:
1. **Length Points (Up to 40 pts)**:
   - $L \ge 16$: 40 points
   - $12 \le L < 16$: 30 to 37.5 points
   - $8 \le L < 12$: 15 to 25.5 points
   - $L < 8$: $L \times 1.8$ points
2. **Character Diversity (Up to 25 pts)**:
   - +6.25 points for each class present (lowercase, uppercase, numbers, symbols).
3. **Entropy Contribution (Up to 25 pts)**:
   - $\min\left(25, \frac{E_{\text{eff}}}{60} \times 25\right)$ (60+ bits achieves maximum entropy credit).
4. **Passphrase Bonus (Up to 10 pts)**:
   - +10 points if length $\ge 14$ and all 4 character classes are present.

### Adversarial Deductions:
- **Exact Common Password Match**: Capped at $\le 10$ points (Immediate *Very Weak*).
- **Embedded Dictionary Word (4+ letters)**: $-25$ points deduction.
- **Disguised Leetspeak Word (`p@ssw0rd`)**: $-20$ points deduction.
- **Predictable Sequence / Keyboard Walk (`12345`, `qwerty`)**: $-15$ points deduction.
- **Repeated Character Pattern (`aaa`, `abcabc`)**: $-10$ to $-15$ points deduction.
- **Length Under 8 Characters**: Hard ceiling at $\le 30$ points.

### Strength Tiers:
| Score Range | Strength Tier | Ring Color | Typical Cracking Difficulty |
| :---: | :---: | :---: | :--- |
| **0 – 24** | **Very Weak** | Red (`#DC2626`) | Instant (seconds / trivial wordlists) |
| **25 – 44** | **Weak** | Orange (`#EA580C`) | Minutes to hours via fast GPU hashes |
| **45 – 64** | **Moderate** | Amber (`#D97706`) | Days to weeks under targeted brute force |
| **65 – 84** | **Strong** | Blue (`#2563EB`) | Years against modern cracking hardware |
| **85 – 100** | **Very Strong** | Green (`#16A34A`) | Cryptographically infeasible offline |

---

## 7. Offensive Threat Models vs. Blue Team Defense

### A. Why Passwords Like `siddarthH@564` Fail in the Real World
A naive calculator assumes uniform randomness across 95 ASCII characters ($95^{13} \approx 5 \times 10^{25}$ combinations, claiming millions of years to crack).

**In reality, attackers do NOT perform blind random brute-force.**  
Attackers study human habits and policy rules:
1. **Targeted Hybrid Mask Attacks (Hashcat `-a 6` / `-a 7`)**:
   Users routinely fulfill complexity requirements with:
   $$\text{[Name / Word]} + \text{[Capital Letter]} + \text{[Symbol]} + \text{[3 Digits]}$$
   *(e.g., `siddarthH@564`, `Admin@2024`, `Welcome#123`)*
2. **Search Space Collapse**:
   $$\text{Names List } (100,000) \times \text{Symbols } (32) \times \text{Numbers } (1,000) \times \text{Case Variants } (2) \approx 6.4 \times 10^9 \text{ combinations}$$
3. **Crack Time on a Modern GPU Rig ($10^{10}\text{ guesses/sec}$)**:
   $$\text{Crack Time} = \frac{6.4 \times 10^9}{10^{10}} \approx \mathbf{0.64 \text{ seconds!}}$$

### B. Defensive Cyber Security Architecture (Blue Team Controls)
1. **Online Protection**:
   - **Adaptive Rate Limiting**: Limit failed attempts per IP and account (e.g., max 5 attempts per 15 minutes).
   - **Exponential Backoff**: Introduce progressive delays (1s, 2s, 4s, 8s) after failures to halt automated scripts.
   - **Multi-Factor Authentication (MFA)**: Enforce FIDO2/WebAuthn hardware keys or TOTP authenticator apps.
2. **Offline Hash Protection**:
   - **Memory-Hard Slow Hashing**: Never use MD5, SHA-256, or NTLM. Enforce **Argon2id** (OWASP recommendation: 64MB memory, 3 iterations) or **bcrypt** (work factor 12+).
   - **Cryptographic Salts & Server Peppers**: 16-byte unique salts stop Rainbow Tables; external HSM/Vault peppers protect against database dumps.

### C. NIST SP 800-63B Password Guidelines
- **Length Over Complexity**: Minimum 12–15 characters.
- **Passphrase Adoption**: Encourage 4-word random passphrases (e.g., `correct horse battery staple`).
- **Abolish 90-Day Forced Expiry**: Stops users from making predictable transformations (`Pass2025!` $\to$ `Pass2026!`).
- **Screen Against Breached Dictionaries**: Block passwords found in known breach corpora (e.g., HaveIBeenPwned).

---

## 8. Automated Unit Testing

### Run JavaScript Tests (31 Unit Tests):
```bash
node tests/test_javascript.js
```
*Verifies entropy calculations, dictionary matching, leetspeak unmasking, hybrid mask penalties, and static zero-telemetry code compliance.*

### Run Python Tests (34 Unit Tests):
```bash
python test_runner.py
# Or using Python's built-in discover:
python -m unittest discover tests -p "test_*.py"
```
*Verifies scoring tiers, mathematical formulas, absence of disk writes or networking, and immediate credential discard.*

---

## 9. Interview Defense & Quick Talking Points

1. **"Why does `siddarthH@564` crack in under a second despite having 13 characters?"**
   * *Answer:* Standard calculators assume uniform random brute-force ($95^{13}$). Adversaries use targeted hybrid mask attacks (`Name + Symbol + 3 Digits`), collapsing search space to $6.4 \times 10^9$ combinations, crackable by modern GPUs in $<1$ second.
2. **"How does this project guarantee privacy?"**
   * *Answer:* 100% volatile memory execution. Zero network calls (`fetch`, `XHR`), zero persistent storage (`localStorage`, cookies), and zero console logging.
3. **"Why is Shannon entropy better than simple character counts?"**
   * *Answer:* Shannon entropy measures actual character distribution uncertainty ($-\sum p_i \log_2 p_i$). A string of repeated characters like `aaaaaaaa` yields 0 bits of Shannon entropy, immediately exposing lack of randomness.

---

## 10. License
Developed for educational and cybersecurity internship demonstration under the MIT License.
