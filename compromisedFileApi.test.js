import fetchCompromisedPackages from './compromisedFileApi.js';

(async () => {
  // Test with a valid URL
  const validUrl = 'https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/refs/heads/main/compromised-packages.txt';
  const data = await fetchCompromisedPackages(validUrl);
  if (typeof data === 'string' && data.length > 0) {
    console.log('PASS: Valid URL returns non-empty string');
  } else {
    console.error('FAIL: Valid URL did not return expected data');
  }

  // Test with an invalid URL
  const invalidUrl = 'https://invalid-url.example.com/does-not-exist.txt';
  const data2 = await fetchCompromisedPackages(invalidUrl);
  if (data2 === ' ') {
    console.log('PASS: Invalid URL returns empty string');
  } else {
    console.error('FAIL: Invalid URL did not return empty string');
  }
})();
