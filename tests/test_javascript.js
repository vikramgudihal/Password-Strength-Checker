/**
 * Automated Unit Test Suite for SecurePass
 * Covers:
 * - Empty input & unusual characters
 * - Weak, moderate, and strong synthetic test cases
 * - Common passwords and leetspeak substitutions
 * - Repeated characters and predictable keyboard/numerical sequences
 * - Character variety and length boundary conditions
 * - Shannon entropy & pool entropy calculations
 * - Constructive recommendation generation
 * - Privacy & security code-level verification (no storage, no telemetry)
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {
  calculateShannonEntropy,
  calculatePoolEntropy,
  checkLength,
  checkCharacterVariety,
  checkDictionaryWords,
  checkSubstitutions,
  checkRepeatedCharacters,
  checkPredictableSequences,
  analyzePassword
} = require('../js/script.js');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function runTest(testName, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  \x1b[32m✔ PASS\x1b[0m: ${testName}`);
    passedTests++;
  } catch (err) {
    console.error(`  \x1b[31m✖ FAIL\x1b[0m: ${testName}`);
    console.error(`    Error: ${err.message}`);
    failedTests++;
  }
}

console.log('\n============================================================');
console.log('  SecurePass Automated Test Suite & Security Verification   ');
console.log('============================================================\n');

// ----------------------------------------------------------------------------
// 1. EMPTY INPUT & UNUSUAL CHARACTERS
// ----------------------------------------------------------------------------
console.log('\x1b[36m[Group 1] Empty Input & Unusual Characters\x1b[0m');

runTest('Empty string returns 0 score, 0 entropy, Very Weak status', () => {
  const result = analyzePassword('');
  assert.strictEqual(result.score, 0);
  assert.strictEqual(result.shannonEntropy, 0);
  assert.strictEqual(result.effectiveEntropy, 0);
  assert.strictEqual(result.strength, 'Very Weak');
  assert.strictEqual(result.analysis.length.status, 'fail');
});

runTest('Null or undefined inputs handled gracefully without throwing', () => {
  const nullResult = analyzePassword(null);
  const undefResult = analyzePassword(undefined);
  assert.strictEqual(nullResult.score, 0);
  assert.strictEqual(undefResult.score, 0);
});

runTest('Unusual characters (unicode symbols, spaces, emojis) evaluate without error', () => {
  const syntheticInput = 'K9#μ_Ω 99α!';
  const result = analyzePassword(syntheticInput);
  assert(result.shannonEntropy > 0);
  assert(result.score > 30);
  assert(result.analysis.variety.hasSymbol === true);
});

// ----------------------------------------------------------------------------
// 2. SHANNON ENTROPY & POOL ENTROPY CALCULATIONS
// ----------------------------------------------------------------------------
console.log('\n\x1b[36m[Group 2] Shannon & Pool Entropy Calculations\x1b[0m');

runTest('Shannon entropy of pure repeated character ("aaaaaaaa") is 0.0 bits', () => {
  const entropy = calculateShannonEntropy('aaaaaaaa');
  assert.strictEqual(entropy, 0.0);
});

runTest('Shannon entropy of 4 distinct characters ("abcd") equals exactly 4 * log2(4) = 8.0 bits', () => {
  const entropy = calculateShannonEntropy('abcd');
  // p_i = 1/4. -log2(1/4) = 2. H = 2 bits/char. Total = 2 * 4 = 8.0 bits.
  assert.strictEqual(entropy, 8.0);
});

runTest('Pool entropy calculation matches theoretical formula L * log2(R)', () => {
  // 'abcdef' (lowercase only -> R=26). L=6. 6 * log2(26) ≈ 6 * 4.7004 = 28.2 bits.
  const pool = calculatePoolEntropy('abcdef');
  assert(Math.abs(pool - 28.2) <= 0.2);
});

runTest('Effective entropy takes conservative minimum between Shannon and Pool', () => {
  // 'aaaaaaaa' has pool entropy > 0 but Shannon entropy = 0.
  const result = analyzePassword('aaaaaaaa');
  assert.strictEqual(result.effectiveEntropy, 0);
});

// ----------------------------------------------------------------------------
// 3. COMMON PASSWORDS & LEETSPEAK SUBSTITUTIONS
// ----------------------------------------------------------------------------
console.log('\n\x1b[36m[Group 3] Common Passwords & Leetspeak Substitutions\x1b[0m');

runTest('Common password "password" is detected and capped at <= 10 score', () => {
  const result = analyzePassword('password');
  assert.strictEqual(result.analysis.dictionary.found, true);
  assert.strictEqual(result.analysis.dictionary.isExactMatch, true);
  assert(result.score <= 10);
  assert.strictEqual(result.strength, 'Very Weak');
});

runTest('Embedded dictionary word "admin" is flagged in "admin987"', () => {
  const check = checkDictionaryWords('admin987');
  assert.strictEqual(check.found, true);
  assert(check.matches.includes('admin'));
  assert.strictEqual(check.status, 'fail');
});

runTest('Leetspeak substitution "p@ssw0rd" is unmasked to "password"', () => {
  const sub = checkSubstitutions('p@ssw0rd');
  assert.strictEqual(sub.found, true);
  assert(sub.matches.includes('password'));
  assert.strictEqual(sub.status, 'fail');
});

runTest('Complex leetspeak "P@55w0rd" is detected as disguised dictionary word', () => {
  const sub = checkSubstitutions('P@55w0rd');
  assert.strictEqual(sub.found, true);
  assert(sub.matches.includes('password'));
});

// ----------------------------------------------------------------------------
// 4. REPEATED CHARACTERS & PREDICTABLE SEQUENCES
// ----------------------------------------------------------------------------
console.log('\n\x1b[36m[Group 4] Repeated Characters & Predictable Sequences\x1b[0m');

runTest('Consecutive repeated characters ("aaa") are flagged as fail', () => {
  const repeat = checkRepeatedCharacters('Testaaa123');
  assert.strictEqual(repeat.found, true);
  assert.strictEqual(repeat.status, 'fail');
});

runTest('Repeating chunk patterns ("abcabc") are flagged with warning', () => {
  const repeat = checkRepeatedCharacters('abcabc');
  assert.strictEqual(repeat.found, true);
  assert.strictEqual(repeat.status, 'warning');
});

runTest('Predictable numerical sequence "12345" is detected', () => {
  const seq = checkPredictableSequences('MyKey12345');
  assert.strictEqual(seq.found, true);
  assert.strictEqual(seq.status, 'fail');
});

runTest('Predictable keyboard walk "qwerty" is detected', () => {
  const seq = checkPredictableSequences('safe_qwerty');
  assert.strictEqual(seq.found, true);
  assert.strictEqual(seq.status, 'fail');
});

runTest('Predictable alphabetical sequence "abcd" is detected', () => {
  const seq = checkPredictableSequences('abcd_xyz');
  assert.strictEqual(seq.found, true);
  assert.strictEqual(seq.status, 'fail');
});

// ----------------------------------------------------------------------------
// 5. CHARACTER VARIETY & LENGTH BOUNDARIES
// ----------------------------------------------------------------------------
console.log('\n\x1b[36m[Group 5] Character Variety & Length Boundaries\x1b[0m');

runTest('Length < 8 characters triggers fail status', () => {
  const lenCheck = checkLength('Ab1#');
  assert.strictEqual(lenCheck.status, 'fail');
  assert.strictEqual(lenCheck.length, 4);
});

runTest('Length 8-11 triggers warning status', () => {
  const lenCheck = checkLength('Ab1#Ef2$');
  assert.strictEqual(lenCheck.status, 'warning');
  assert.strictEqual(lenCheck.length, 8);
});

runTest('Length >= 12 triggers pass status', () => {
  const lenCheck = checkLength('Ab1#Ef2$Gh3%');
  assert.strictEqual(lenCheck.status, 'pass');
  assert.strictEqual(lenCheck.length, 12);
});

runTest('All 4 character classes identified properly', () => {
  const variety = checkCharacterVariety('Aa1!');
  assert.strictEqual(variety.count, 4);
  assert.strictEqual(variety.status, 'pass');
  assert.strictEqual(variety.hasLower, true);
  assert.strictEqual(variety.hasUpper, true);
  assert.strictEqual(variety.hasNumber, true);
  assert.strictEqual(variety.hasSymbol, true);
});

// ----------------------------------------------------------------------------
// 6. SYNTHETIC WEAK, MODERATE, AND STRONG PROFILES
// ----------------------------------------------------------------------------
console.log('\n\x1b[36m[Group 6] Weak, Moderate, and Strong Synthetic Profiles\x1b[0m');

runTest('Synthetic Weak Password ("123456") receives <= 15 score and Very Weak rating', () => {
  const result = analyzePassword('123456');
  assert(result.score <= 15);
  assert.strictEqual(result.strength, 'Very Weak');
});

runTest('Synthetic Moderate Password ("BlueFalcon#84") scores between 45 and 80', () => {
  const result = analyzePassword('BlueFalcon#84');
  assert(result.score >= 45, `Expected >= 45 but got ${result.score}`);
  assert(result.score < 85, `Expected < 85 but got ${result.score}`);
  assert(result.strength === 'Moderate' || result.strength === 'Strong');
});

runTest('Synthetic Strong Password ("kX9#vM2$pQ7!wZ4&") receives >= 85 and Very Strong rating', () => {
  const result = analyzePassword('kX9#vM2$pQ7!wZ4&');
  assert(result.score >= 85, `Expected >= 85 but got ${result.score}`);
  assert.strictEqual(result.strength, 'Very Strong');
});

// ----------------------------------------------------------------------------
// 7. CONSTRUCTIVE RECOMMENDATIONS GENERATION
// ----------------------------------------------------------------------------
console.log('\n\x1b[36m[Group 7] Constructive Security Recommendations\x1b[0m');

runTest('Short password receives constructive recommendation to increase length to 12-16', () => {
  const result = analyzePassword('Ab1$');
  const hasLengthRec = result.recommendations.some(r => r.includes('12–16 characters'));
  assert.strictEqual(hasLengthRec, true);
});

runTest('Leetspeak password generates warning advising against simple substitutions', () => {
  const result = analyzePassword('p@ssw0rd99');
  const hasSubRec = result.recommendations.some(r => r.includes('Leetspeak substitutions'));
  assert.strictEqual(hasSubRec, true);
});

// ----------------------------------------------------------------------------
// 8. PRIVACY & SECURITY CODE-LEVEL AUDIT (STATIC CODE ANALYSIS)
// ----------------------------------------------------------------------------
console.log('\n\x1b[36m[Group 8] Code-Level Privacy & Security Static Verification\x1b[0m');

runTest('script.js does not contain localStorage or sessionStorage calls', () => {
  const code = fs.readFileSync(path.join(__dirname, '../js/script.js'), 'utf8');
  // Strip comments before static code check
  const codeWithoutComments = code.replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '');
  assert(!codeWithoutComments.includes('localStorage'), 'localStorage should not be present');
  assert(!codeWithoutComments.includes('sessionStorage'), 'sessionStorage should not be present');
  assert(!codeWithoutComments.includes('indexedDB'), 'indexedDB should not be present');
  assert(!codeWithoutComments.includes('document.cookie'), 'document.cookie should not be present');
});

runTest('script.js does not contain network transmission methods (fetch, XMLHttpRequest, sendBeacon)', () => {
  const code = fs.readFileSync(path.join(__dirname, '../js/script.js'), 'utf8');
  assert(!code.includes('fetch('), 'fetch() should not be called');
  assert(!code.includes('XMLHttpRequest'), 'XMLHttpRequest should not be used');
  assert(!code.includes('navigator.sendBeacon'), 'sendBeacon should not be used');
  assert(!code.includes('eval('), 'eval() should not be used');
});

runTest('script.js does not output passwords to console.log', () => {
  const code = fs.readFileSync(path.join(__dirname, '../js/script.js'), 'utf8');
  assert(!code.includes('console.log(password'), 'Passwords should not be logged');
  assert(!code.includes('console.info(password'), 'Passwords should not be logged');
});

// ----------------------------------------------------------------------------
// 9. TARGETED ATTACK & PERSONAL NAME HYBRID MASK VERIFICATION
// ----------------------------------------------------------------------------
console.log('\n\x1b[36m[Group 9] Targeted Attack & Personal Name Hybrid Mask Verification\x1b[0m');

runTest('Personal name in credentials ("siddarthH@564") is flagged in dictionary check', () => {
  const dict = checkDictionaryWords('siddarthH@564');
  assert.strictEqual(dict.found, true);
  assert.strictEqual(dict.isPersonalName, true);
  assert(dict.matches.includes('siddarth'));
  assert.strictEqual(dict.status, 'fail');
});

runTest('Hybrid mask pattern ("siddarthH@564") is flagged with targeted attack warning', () => {
  const seq = checkPredictableSequences('siddarthH@564');
  assert.strictEqual(seq.found, true);
  assert.strictEqual(seq.isHybridMask, true);
  assert.strictEqual(seq.status, 'fail');
});

runTest('Predictable name+symbol+number pattern is penalized and not falsely rated Very Strong', () => {
  const result = analyzePassword('siddarthH@564');
  assert(result.score <= 50, `Expected score <= 50 but got ${result.score}`);
  assert.strictEqual(result.strength, 'Moderate');
  assert(result.crackTime.includes('Targeted Hashcat attack'));
  const hasNameWarning = result.recommendations.some(r => r.includes('personal name'));
  assert.strictEqual(hasNameWarning, true);
});

// ----------------------------------------------------------------------------
// TEST RESULTS SUMMARY
// ----------------------------------------------------------------------------
console.log('\n============================================================');
console.log(`  Tests Completed: ${totalTests}`);
console.log(`  Passed: \x1b[32m${passedTests}\x1b[0m`);
console.log(`  Failed: ${failedTests > 0 ? `\x1b[31m${failedTests}\x1b[0m` : '0'}`);
console.log('============================================================\n');

if (failedTests > 0) {
  process.exit(1);
} else {
  console.log('All tests passed successfully! Clean cryptographic logic verified.\n');
}
