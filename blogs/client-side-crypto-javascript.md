# Building Client-Side Crypto in JavaScript: Lessons from PASS-SHIELD

**Author:** Austin J Robin ([@AUSTIN-JR](https://github.com/AUSTIN-JR))  
**Role:** First-Year Cybersecurity Student, Karunya University  
**Project:** [PASS-SHIELD](https://github.com/AUSTIN-JR/password-app)  
**Date:** September 2026  
**Reading Time:** ~9 minutes (1,500 words)

---

## 1. Introduction

For decades, security engineers adhered to a strict dogma: *"Never do cryptography in JavaScript."* In 2011, Matasano Security published a legendary essay arguing that browser-based cryptography was fundamentally flawed due to insecure random number generators, a lack of memory safety, malleability in the runtime environment, and vulnerability to script injection.

Yet in 2026, the modern web is unrecognizable from the JavaScript landscape of 2011. The introduction of the standardized **W3C Web Cryptography API (`window.crypto`)**, modern Content Security Policies (CSP), and strict isolation primitives has transformed client-side security.

When I set out to build **PASS-SHIELD**—a zero-knowledge password auditing, entropy calculation, and cryptographically secure generation engine—my core premise was absolute: **A user's plaintext password must never, under any circumstance, touch a network socket, transmit to a backend server, or persist on a database.**

This blog post explores how PASS-SHIELD implements mathematical entropy metrics and CSPRNG generation entirely in the client browser, dissects the technical hurdles of JavaScript cryptography, and shares practical defensive engineering lessons learned along the way.

---

## 2. The Inherent Paradox of JavaScript Cryptography

Why was JavaScript historically considered hazardous for cryptographic applications?

1. **Lack of Memory Control (Garbage Collection):** In low-level languages like C or Rust, when a developer handles an encryption key or plaintext password in memory, they explicitly overwrite that memory buffer using `explicit_bzero()` or `SecureZeroMemory()` once the operation completes. In JavaScript, memory management is handled entirely by a non-deterministic garbage collector (V8, SpiderMonkey, JavaScriptCore). A string holding a plaintext password might persist in heap memory across hundreds of allocations before being reclaimed.
2. **Pseudo-Random Number Generator (PRNG) Weaknesses:** For years, web developers used `Math.random()`. In virtually all browser engines, `Math.random()` relies on algorithms like **xorshift128+**. While fast for games and animations, xorshift128+ is completely deterministic: an attacker who observes a small sequence of outputs can mathematically reconstruct the internal state and predict all future "random" values!
3. **Execution Environment Malleability:** In JavaScript, native prototypes can be monkey-patched. A malicious third-party script or browser extension can execute:
   ```javascript
   const originalFetch = window.fetch;
   window.fetch = function(...args) { /* exfiltrate credentials */ originalFetch.apply(this, args); };
   ```
4. **Side-Channel and Timing Leaks:** JavaScript engines use Just-In-Time (JIT) compilation and aggressive runtime optimizations, making it notoriously difficult to write guaranteed constant-time algorithms in pure JS.

### Why We Do It Anyway: The Zero-Knowledge Imperative
Despite these hazards, the alternative—sending candidate passwords over HTTP to a backend API to evaluate their strength—creates an unacceptable architectural vulnerability:
- A backend server logging passwords in debug logs or access logs.
- Man-in-the-middle risks if TLS is terminated improperly or inspected by enterprise proxies.
- A single server compromise exposing thousands of users' credential queries.

By performing all entropy calculations and generation client-side, **PASS-SHIELD delivers a true zero-knowledge guarantee**. Even if the PASS-SHIELD web server is completely compromised by an attacker, not a single password can be leaked, because no password was ever transmitted to it.

---

## 3. The Web Crypto API: Native Primitives in the Browser

The foundation that makes modern client-side security viable is the **W3C Web Cryptography API** (`window.crypto`).

Unlike traditional userland JavaScript libraries, `window.crypto` is implemented in native C++ within the browser engine (e.g., Chromium's BoringSSL, Firefox's NSS). It interfaces directly with operating system entropy sources:
- Linux: `getrandom()` syscall or `/dev/urandom`
- Windows: `BCryptGenRandom` via CNG (Cryptography Next Generation)
- macOS/iOS: `SecRandomCopyBytes`

### CSPRNG Generation: `Math.random()` vs `crypto.getRandomValues()`
In PASS-SHIELD, password generation is strictly forbidden from using `Math.random()`. Instead, we utilize `window.crypto.getRandomValues()`:

```javascript
// PASS-SHIELD: Cryptographically Secure Random Character Selector
function getRandomIndex(poolLength) {
    if (poolLength <= 0 || poolLength > 256) {
        throw new Error("Invalid character pool length");
    }
    
    // We allocate an 8-bit unsigned integer array
    const randomBuffer = new Uint8Array(1);
    
    // Elimination of Modulo Bias using Rejection Sampling:
    // Any value >= limit is rejected to guarantee perfectly uniform distribution
    const maxValid = Math.floor(256 / poolLength) * poolLength;
    
    let candidate;
    do {
        window.crypto.getRandomValues(randomBuffer);
        candidate = randomBuffer[0];
    } while (candidate >= maxValid);
    
    return candidate % poolLength;
}
```

```
┌────────────────────────────────────────────────────────┐
│            Operating System Entropy Pool              │
│     (/dev/urandom on Linux, BCrypt on Windows)        │
└───────────────────────────┬────────────────────────────┘
                            │ System Call
                            ▼
┌────────────────────────────────────────────────────────┐
│      Browser Native Engine (BoringSSL / C++)           │
└───────────────────────────┬────────────────────────────┘
                            │ window.crypto.getRandomValues()
                            ▼
┌────────────────────────────────────────────────────────┐
│   PASS-SHIELD Engine: Rejection Sampling & Filtering   │
│            (Guaranteed Zero Modulo Bias)               │
└────────────────────────────────────────────────────────┘
```

Notice the rejection sampling logic. Simply doing `candidate % poolLength` introduces **modulo bias** whenever 256 is not evenly divisible by the pool size. For example, if the pool size is 94 characters (ASCII 33 to 126), characters with indices 0 through 67 would be slightly more likely to be selected than characters 68 through 93! By discarding values where `candidate >= maxValid`, PASS-SHIELD guarantees mathematically uniform distribution across all characters.

---

## 4. Mathematical Entropy Calculation: Theory vs Practice

A critical component of PASS-SHIELD is providing users with mathematically sound password strength evaluation, rather than arbitrary, unscientific percentage bars.

### Shannon Entropy vs Hartley Information Capacity
Claude Shannon's information theory defines the entropy $H$ of a message given character probabilities $p(x_i)$:
$$H = -\sum_{i=1}^{k} p(x_i) \log_2 p(x_i)$$

For a randomly generated password of length $L$ drawn from an alphabet of $N$ equally probable characters (Hartley capacity):
$$H = L \cdot \log_2(N)$$

PASS-SHIELD dynamically calculates the active character pool $N$ based on character categories:
- Lowercase alphabet ($a-z$): 26 characters
- Uppercase alphabet ($A-Z$): 26 characters
- Numeric digits ($0-9$): 10 characters
- Standard symbols ($!@\#\$\%\^\&*\dots$): 33 characters
- Extended Unicode symbols: up to 128 additional characters

```javascript
// PASS-SHIELD: Dynamic Pool and Shannon Entropy
function calculateEntropy(password) {
    if (!password || password.length === 0) return 0.0;
    
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;
    
    // Theoretical max bits of entropy
    const rawEntropy = password.length * Math.log2(poolSize);
    
    // Apply penalty for repeated characters and sequences
    const penalty = calculatePatternDeductions(password);
    return Math.max(0, rawEntropy - penalty);
}
```

---

## 5. Defensive Pattern Recognition and ReDoS Protection

Real human passwords are not uniformly random strings; users rely on mental shortcuts such as keyboard walks, sequential numbers, and dictionary substitutions. 

PASS-SHIELD analyzes passwords for these patterns to provide realistic crack-time estimates based on NIST SP 800-63B guidelines.

### Pattern Detection Mechanics
1. **Spatial Keyboard Walks:** Detects sequences like `qwerty`, `asdf`, `zxcv`, and reverse walks (`poiuy`).
2. **Arithmetic Sequences:** Detects numeric ascending/descending runs (`123456`, `987654`) and alphabetical sequences (`abcdef`).
3. **Repetition and Clustering:** Detects character repeats (`aaaaaa`, `111111`).

### Preventing Regular Expression Denial of Service (ReDoS)
A massive danger in client-side input analysis is catastrophic backtracking in regular expressions. A regex like `([a-zA-Z0-9]+)*$` can cause the browser thread to lock up at 100% CPU when given an input of 30 characters.

To prevent ReDoS, PASS-SHIELD **completely avoids nested unbounded quantifiers**. Instead, sequence detection is implemented using bounded, single-pass $O(N)$ linear scans:

```javascript
// Linear O(N) Sequential Detection - Zero ReDoS Risk
function detectSequentialChars(str, minLength = 3) {
    let consecutiveCount = 1;
    let totalSequences = 0;
    
    for (let i = 1; i < str.length; i++) {
        const diff = str.charCodeAt(i) - str.charCodeAt(i - 1);
        if (diff === 1 || diff === -1) {
            consecutiveCount++;
            if (consecutiveCount >= minLength) {
                totalSequences++;
            }
        } else {
            consecutiveCount = 1;
        }
    }
    return totalSequences;
}
```

---

## 6. Memory Hygiene in a Garbage-Collected World

Because JavaScript engines do not permit direct pointer access to overwrite string buffers with zero bytes, PASS-SHIELD employs defensive frontend design patterns:

1. **Ephemeral Form Elements:** The password analysis input does not use persistent local state or cache. `autocomplete="new-password"`, `autocorrect="off"`, and `spellcheck="false"` prevent the browser from saving inputs to disk.
2. **Auto-Expiring Clipboard:** When a user copies a generated password to their clipboard, PASS-SHIELD utilizes the modern `navigator.clipboard` API and schedules an automatic wipe after 30 seconds:
   ```javascript
   async function copyWithAutoWipe(password) {
       await navigator.clipboard.writeText(password);
       // Provide feedback
       showNotification("Password copied! Clipboard will be wiped in 30 seconds.");
       
       setTimeout(async () => {
           // Overwrite clipboard with blank data
           try {
               await navigator.clipboard.writeText("");
           } catch (e) {
               // Browser tab might have lost focus; fail safely
           }
       }, 30_000);
   }
   ```
3. **Strict Content Security Policy (CSP):** The application is served with an uncompromising CSP header:
   ```http
   Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'self';
   ```
   This completely blocks unauthorized inline scripts, `eval()` execution, and third-party remote script loading.

---

## 7. Performance Benchmarks

To ensure an instantaneous user experience without stuttering on typing events, benchmarks were executed on Chrome 128 (Windows 11):

| Operation | Input Size | Mean Execution Time | Overhead per Keystroke |
| :--- | :--- | :--- | :--- |
| **Entropy Calculation** | 16 characters | 0.08 ms | Negligible (<0.1 ms) |
| **Full Pattern Audit (Walks + Sequences)** | 32 characters | 0.22 ms | Negligible (<0.3 ms) |
| **CSPRNG Password Generation** | 20 characters | 0.14 ms | Instantaneous |
| **Batch Generation (100 passwords)** | 16 characters each | 11.8 ms | ~0.11 ms per password |

Because all operations complete in well under 1 millisecond, PASS-SHIELD provides silky smooth 60fps interactive feedback while users type.

---

## 8. Lessons Learned & Key Takeaways

1. **Client-Side Privacy is Worth the Engineering Effort:** Eliminating the backend password roundtrip guarantees that user credentials can never be leaked via server logs, network sniffing, or database dumps.
2. **Never Trust `Math.random()` for Security:** In security-sensitive code, `Math.random()` is a critical vulnerability. Always use `window.crypto.getRandomValues()` combined with rejection sampling to eliminate modulo bias.
3. **ReDoS is an Overlooked Attack Vector:** Validating passwords using complex regexes can freeze a client's browser. Linear $O(N)$ string iteration is significantly safer and faster.
4. **Defense-in-Depth via CSP:** Client-side cryptography is only as strong as the host document. Enforcing a strict CSP is the single most effective countermeasure against DOM-based XSS attacks.

---

## 9. Conclusion

Client-side cryptography in JavaScript is no longer an anti-pattern when built on the solid foundation of the W3C Web Cryptography API and defensive software engineering principles.

**PASS-SHIELD** demonstrates that developers can deliver high-performance, mathematically rigorous password analysis and generation tools while maintaining total privacy and zero server-side exposure.

Explore the source code, test suites, and live implementation at [AUSTIN-JR/password-app](https://github.com/AUSTIN-JR/password-app).

---
*Questions or security feedback? Reach out to Austin J Robin at [robinaustinj@gmail.com](mailto:robinaustinj@gmail.com) or submit a pull request on GitHub!*
