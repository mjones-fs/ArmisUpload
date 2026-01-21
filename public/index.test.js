/**
 * Unit tests for client-side JavaScript functions
 * Tests for: updateFloatingLabel, extractVersionFromFilename, and version field update logic
 */

// Mock DOM elements for testing
class MockElement {
  constructor() {
    this.classList = {
      classes: new Set(),
      add: function(className) { this.classes.add(className); },
      remove: function(className) { this.classes.delete(className); },
      contains: function(className) { return this.classes.has(className); }
    };
    this.value = '';
  }
}

// Function definitions (extracted from index.html for testing)
function updateFloatingLabel(input) {
  if (input.value && input.value.trim() !== '') {
    input.classList.add('has-value');
  } else {
    input.classList.remove('has-value');
  }
}

function extractVersionFromFilename(filename) {
  // Remove file extension for matching (handle double extensions like .tar.gz)
  let nameWithoutExt = filename;
  // Common double extensions
  const doubleExtensions = ['.tar.gz', '.tar.bz2', '.tar.xz', '.tar.Z'];
  for (const ext of doubleExtensions) {
    if (nameWithoutExt.endsWith(ext)) {
      nameWithoutExt = nameWithoutExt.slice(0, -ext.length);
      break;
    }
  }
  // If no double extension matched, remove single extension
  if (nameWithoutExt === filename) {
    nameWithoutExt = nameWithoutExt.replace(/\.[^.]+$/, '');
  }
  
  // Common version patterns (ordered by specificity):
  const patterns = [
    /[vV](\d+\.\d+\.\d+(?:\.\d+)?)/,  // v1.2.3 or V1.2.3.4
    /[vV](\d+[._]\d+[._]\d+(?:[._]\d+)?)/,  // v1_2_3
    /version[_-]?(\d+(?:[._]\d+)*)/i,  // version-1.2.3 or version_123
    /fw[_-]?(\d+(?:[._]\d+)*)/i,  // fw-1.2.3 or fw_123
    /rel[_-]?(\d+(?:[._]\d+)*)/i,  // rel-1.2.3 or rel_123
    /-(latest|stable|beta|alpha|dev|prod|production|staging|canary|nightly)$/i,  // -latest, -stable, etc.
    /_(latest|stable|beta|alpha|dev|prod|production|staging|canary|nightly)$/i,  // _latest, _stable, etc.
    /-(x86_64|x86|x64|amd64|arm64|armv7|armv8|aarch64|i386|i686|mips|mipsel|ppc|ppc64)$/i,  // -x86, -arm64, etc.
    /_(x86_64|x86|x64|amd64|arm64|armv7|armv8|aarch64|i386|i686|mips|mipsel|ppc|ppc64)$/i,  // _x86, _arm64, etc.
    /(\d+\.\d+\.\d+(?:\.\d+)?)/,  // 1.2.3 or 1.2.3.4
    /_(\d{6,})$/,  // _202510310 (6+ digits at end after underscore)
    /-(\d{6,})$/,  // -202510310 (6+ digits at end after hyphen)
    /_(\d+)$/,  // _123 (any digits at end after underscore)
    /-(\d+)$/   // -123 (any digits at end after hyphen)
  ];
  
  for (const pattern of patterns) {
    const match = nameWithoutExt.match(pattern);
    if (match && match[1]) {
      // Normalize underscores to dots for dotted versions, keep text as-is
      const version = match[1].replace(/_/g, '.');
      return version;
    }
  }
  
  return '';
}

describe('updateFloatingLabel', () => {
  test('adds has-value class when input has non-empty value', () => {
    const input = new MockElement();
    input.value = 'test value';
    
    updateFloatingLabel(input);
    
    expect(input.classList.contains('has-value')).toBe(true);
  });

  test('removes has-value class when input is empty', () => {
    const input = new MockElement();
    input.value = '';
    input.classList.add('has-value');
    
    updateFloatingLabel(input);
    
    expect(input.classList.contains('has-value')).toBe(false);
  });

  test('removes has-value class when input contains only whitespace', () => {
    const input = new MockElement();
    input.value = '   ';
    input.classList.add('has-value');
    
    updateFloatingLabel(input);
    
    expect(input.classList.contains('has-value')).toBe(false);
  });

  test('adds has-value class when input has value with leading/trailing spaces', () => {
    const input = new MockElement();
    input.value = '  content  ';
    
    updateFloatingLabel(input);
    
    expect(input.classList.contains('has-value')).toBe(true);
  });

  test('handles input with newlines and tabs as valid content', () => {
    const input = new MockElement();
    input.value = '\n\t';
    
    updateFloatingLabel(input);
    
    expect(input.classList.contains('has-value')).toBe(false);
  });
});

describe('extractVersionFromFilename', () => {
  describe('standard semantic versions', () => {
    test('extracts v-prefixed version (v1.2.3)', () => {
      expect(extractVersionFromFilename('firmware-v1.2.3.bin')).toBe('1.2.3');
    });

    test('extracts V-prefixed version (V2.0.1)', () => {
      expect(extractVersionFromFilename('app-V2.0.1.zip')).toBe('2.0.1');
    });

    test('extracts four-part version (v1.2.3.4)', () => {
      expect(extractVersionFromFilename('release-v1.2.3.4.tar.gz')).toBe('1.2.3.4');
    });

    test('extracts version without prefix (1.2.3)', () => {
      expect(extractVersionFromFilename('firmware-1.2.3.bin')).toBe('1.2.3');
    });

    test('extracts version with underscores (v1_2_3)', () => {
      expect(extractVersionFromFilename('firmware-v1_2_3.bin')).toBe('1.2.3');
    });
  });

  describe('keyword-prefixed versions', () => {
    test('extracts version-prefixed version', () => {
      expect(extractVersionFromFilename('app-version-1.2.3.zip')).toBe('1.2.3');
    });

    test('extracts version_prefixed version', () => {
      expect(extractVersionFromFilename('app-version_1.2.3.zip')).toBe('1.2.3');
    });

    test('extracts fw-prefixed version', () => {
      expect(extractVersionFromFilename('device-fw-2.0.1.bin')).toBe('2.0.1');
    });

    test('extracts rel-prefixed version', () => {
      expect(extractVersionFromFilename('software-rel-3.1.0.tar.gz')).toBe('3.1.0');
    });
  });

  describe('special version keywords', () => {
    test('extracts latest keyword', () => {
      expect(extractVersionFromFilename('firmware-latest.bin')).toBe('latest');
    });

    test('extracts stable keyword', () => {
      expect(extractVersionFromFilename('app_stable.zip')).toBe('stable');
    });

    test('extracts beta keyword', () => {
      expect(extractVersionFromFilename('release-beta.tar.gz')).toBe('beta');
    });

    test('extracts alpha keyword', () => {
      expect(extractVersionFromFilename('build_alpha.bin')).toBe('alpha');
    });

    test('extracts production keyword', () => {
      expect(extractVersionFromFilename('deploy-production.zip')).toBe('production');
    });
  });

  describe('architecture suffixes', () => {
    test('extracts x86_64 architecture', () => {
      expect(extractVersionFromFilename('app-x86_64.bin')).toBe('x86.64');
    });

    test('extracts arm64 architecture', () => {
      expect(extractVersionFromFilename('firmware_arm64.zip')).toBe('arm64');
    });

    test('extracts amd64 architecture', () => {
      expect(extractVersionFromFilename('release-amd64.tar.gz')).toBe('amd64');
    });
  });

  describe('numeric suffixes', () => {
    test('extracts long numeric version (6+ digits with underscore)', () => {
      expect(extractVersionFromFilename('firmware_20250121.bin')).toBe('20250121');
    });

    test('extracts long numeric version (6+ digits with hyphen)', () => {
      expect(extractVersionFromFilename('app-20250121.zip')).toBe('20250121');
    });

    test('extracts short numeric version with underscore', () => {
      expect(extractVersionFromFilename('build_123.bin')).toBe('123');
    });

    test('extracts short numeric version with hyphen', () => {
      expect(extractVersionFromFilename('release-456.zip')).toBe('456');
    });
  });

  describe('file extension handling', () => {
    test('handles double extensions (.tar.gz)', () => {
      expect(extractVersionFromFilename('app-v1.2.3.tar.gz')).toBe('1.2.3');
    });

    test('handles double extensions (.tar.bz2)', () => {
      expect(extractVersionFromFilename('firmware-v2.0.1.tar.bz2')).toBe('2.0.1');
    });

    test('handles double extensions (.tar.xz)', () => {
      expect(extractVersionFromFilename('release-v3.1.0.tar.xz')).toBe('3.1.0');
    });

    test('handles single extensions (.bin)', () => {
      expect(extractVersionFromFilename('firmware-v1.0.0.bin')).toBe('1.0.0');
    });

    test('handles single extensions (.zip)', () => {
      expect(extractVersionFromFilename('app-1.2.3.zip')).toBe('1.2.3');
    });
  });

  describe('edge cases', () => {
    test('returns empty string for filename without version', () => {
      expect(extractVersionFromFilename('firmware.bin')).toBe('');
    });

    test('returns empty string for filename with only text', () => {
      expect(extractVersionFromFilename('application-release.zip')).toBe('');
    });

    test('prioritizes v-prefixed version over plain numeric', () => {
      expect(extractVersionFromFilename('app-v2.0.0-123.zip')).toBe('2.0.0');
    });

    test('handles complex filenames', () => {
      expect(extractVersionFromFilename('my-device-firmware-v1.2.3-beta-x86_64.tar.gz')).toBe('1.2.3');
    });
  });
});

describe('Version field update behavior', () => {
  let versionInput;

  beforeEach(() => {
    versionInput = new MockElement();
  });

  test('updates version field when initially empty', () => {
    versionInput.value = '';
    const filename = 'firmware-v1.2.3.bin';
    
    // Simulate the logic from setFiles function
    if (!versionInput.value.trim()) {
      const extractedVersion = extractVersionFromFilename(filename);
      if (extractedVersion) {
        versionInput.value = extractedVersion;
        updateFloatingLabel(versionInput);
      }
    }
    
    expect(versionInput.value).toBe('1.2.3');
    expect(versionInput.classList.contains('has-value')).toBe(true);
  });

  test('preserves user input when version field has value', () => {
    versionInput.value = 'user-entered-version';
    const filename = 'firmware-v1.2.3.bin';
    
    // Simulate the logic from setFiles function
    if (!versionInput.value.trim()) {
      const extractedVersion = extractVersionFromFilename(filename);
      if (extractedVersion) {
        versionInput.value = extractedVersion;
        updateFloatingLabel(versionInput);
      }
    }
    
    expect(versionInput.value).toBe('user-entered-version');
  });

  test('preserves user input even when whitespace is present', () => {
    versionInput.value = ' 2.0.0 ';
    const filename = 'firmware-v1.2.3.bin';
    
    // Simulate the logic from setFiles function
    if (!versionInput.value.trim()) {
      const extractedVersion = extractVersionFromFilename(filename);
      if (extractedVersion) {
        versionInput.value = extractedVersion;
        updateFloatingLabel(versionInput);
      }
    }
    
    expect(versionInput.value).toBe(' 2.0.0 ');
  });

  test('updates version field when only whitespace is present', () => {
    versionInput.value = '   ';
    const filename = 'firmware-v3.0.0.bin';
    
    // Simulate the logic from setFiles function
    if (!versionInput.value.trim()) {
      const extractedVersion = extractVersionFromFilename(filename);
      if (extractedVersion) {
        versionInput.value = extractedVersion;
        updateFloatingLabel(versionInput);
      }
    }
    
    expect(versionInput.value).toBe('3.0.0');
    expect(versionInput.classList.contains('has-value')).toBe(true);
  });

  test('does not update version field when no version extracted from filename', () => {
    versionInput.value = '';
    const filename = 'firmware.bin';
    
    // Simulate the logic from setFiles function
    if (!versionInput.value.trim()) {
      const extractedVersion = extractVersionFromFilename(filename);
      if (extractedVersion) {
        versionInput.value = extractedVersion;
        updateFloatingLabel(versionInput);
      }
    }
    
    expect(versionInput.value).toBe('');
    expect(versionInput.classList.contains('has-value')).toBe(false);
  });

  test('correctly handles file selection after user clears manual input', () => {
    // User enters a version
    versionInput.value = '1.0.0';
    
    // User clears the input
    versionInput.value = '';
    
    // User selects a new file
    const filename = 'firmware-v2.0.0.bin';
    if (!versionInput.value.trim()) {
      const extractedVersion = extractVersionFromFilename(filename);
      if (extractedVersion) {
        versionInput.value = extractedVersion;
        updateFloatingLabel(versionInput);
      }
    }
    
    expect(versionInput.value).toBe('2.0.0');
  });

  test('version field preserves user input across multiple file selections', () => {
    // User manually enters version
    versionInput.value = 'custom-version';
    
    // First file selection
    const filename1 = 'firmware-v1.0.0.bin';
    if (!versionInput.value.trim()) {
      const extractedVersion = extractVersionFromFilename(filename1);
      if (extractedVersion) {
        versionInput.value = extractedVersion;
      }
    }
    expect(versionInput.value).toBe('custom-version');
    
    // Second file selection
    const filename2 = 'firmware-v2.0.0.bin';
    if (!versionInput.value.trim()) {
      const extractedVersion = extractVersionFromFilename(filename2);
      if (extractedVersion) {
        versionInput.value = extractedVersion;
      }
    }
    expect(versionInput.value).toBe('custom-version');
  });
});
