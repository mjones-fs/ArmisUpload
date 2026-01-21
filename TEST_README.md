# Unit Tests Documentation

## Overview
This document describes the unit tests created for the ArmisUpload application's client-side JavaScript functions.

## Test File
`public/index.test.js`

## Running Tests
```bash
npm test
```

## Test Coverage

### 1. updateFloatingLabel Function Tests
Tests the floating label behavior for input fields.

**Test Cases:**
- ✅ Adds `has-value` class when input has non-empty value
- ✅ Removes `has-value` class when input is empty
- ✅ Removes `has-value` class when input contains only whitespace
- ✅ Adds `has-value` class when input has value with leading/trailing spaces
- ✅ Handles input with newlines and tabs as whitespace

**Purpose:** Ensures the UI floating labels work correctly based on input field state.

---

### 2. extractVersionFromFilename Function Tests
Tests the version extraction logic from various filename patterns.

#### Standard Semantic Versions
- ✅ `v1.2.3` format (v-prefixed)
- ✅ `V1.2.3` format (capital V-prefixed)
- ✅ `v1.2.3.4` format (four-part version)
- ✅ `1.2.3` format (no prefix)
- ✅ `v1_2_3` format (underscore-separated)

#### Keyword-Prefixed Versions
- ✅ `version-1.2.3` format
- ✅ `version_1.2.3` format
- ✅ `fw-2.0.1` format (firmware)
- ✅ `rel-3.1.0` format (release)

#### Special Version Keywords
- ✅ `latest`, `stable`, `beta`, `alpha`, `production`, `staging`, `canary`, `nightly`, `dev`, `prod`

#### Architecture Suffixes
- ✅ x86_64, x86, amd64, arm64, armv7, armv8, aarch64, i386, etc.

#### Numeric Suffixes
- ✅ Long numeric versions (6+ digits): `_20250121`, `-20250121`
- ✅ Short numeric versions: `_123`, `-456`

#### File Extension Handling
- ✅ Double extensions: `.tar.gz`, `.tar.bz2`, `.tar.xz`
- ✅ Single extensions: `.bin`, `.zip`, `.exe`, etc.

#### Edge Cases
- ✅ Returns empty string for filenames without version
- ✅ Prioritizes v-prefixed versions over plain numeric
- ✅ Handles complex filenames with multiple patterns

**Purpose:** Ensures accurate version extraction from uploaded firmware/software filenames.

---

### 3. Version Field Update Behavior Tests
Tests the critical logic that preserves user input while auto-populating from filenames.

**Test Cases:**
- ✅ Updates version field when initially empty
- ✅ **Preserves user input when version field already has a value**
- ✅ **Preserves user input even when it contains whitespace**
- ✅ Updates version field when it contains only whitespace
- ✅ Does not update when no version can be extracted from filename
- ✅ Correctly handles file selection after user clears manual input
- ✅ **Preserves user input across multiple file selections**

**Purpose:** Validates the most important user experience feature - the version field only auto-fills when empty, preserving any manual user input.

---

## Key Implementation Details

### Mock DOM Elements
The tests use a `MockElement` class that simulates browser DOM elements with:
- `value` property
- `classList` with `add()`, `remove()`, and `contains()` methods

This allows testing without a browser environment.

### Test Framework
- **Jest** (v29.7.0) is used as the testing framework
- Tests are written using Jest's `describe`, `test`, `expect`, and `beforeEach` functions
- The project uses ES modules, so Jest runs with the `--experimental-vm-modules` flag

### Test Organization
Tests are organized into three main describe blocks:
1. `updateFloatingLabel` - 5 tests
2. `extractVersionFromFilename` - 30 tests (organized into sub-categories)
3. `Version field update behavior` - 7 tests

**Total: 42 tests, all passing ✅**

---

## Example Test Output
```
PASS  public/index.test.js
  updateFloatingLabel
    ✓ adds has-value class when input has non-empty value
    ✓ removes has-value class when input is empty
    ...
  extractVersionFromFilename
    ✓ extracts v-prefixed version (v1.2.3)
    ✓ extracts version with underscores (v1_2_3)
    ...
  Version field update behavior
    ✓ updates version field when initially empty
    ✓ preserves user input when version field has value
    ...

Test Suites: 1 passed, 1 total
Tests:       42 passed, 42 total
```

---

## Adding More Tests
To add additional tests:

1. Open `public/index.test.js`
2. Add new test cases within existing `describe` blocks or create new ones
3. Follow the existing pattern using Jest's `test()` or `it()` functions
4. Run `npm test` to verify

## Notes
- The test file includes copies of the functions being tested to enable isolated unit testing
- Any changes to the functions in `index.html` should be reflected in the test file
- All tests validate the exact behavior specified in your requirements
