import fetchCompromisedPackages from '../compromisedFileApi.js';
import {jest} from '@jest/globals'
const URL ='https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/refs/heads/main/compromised-packages.txt';

const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('fetchCompromisedPackages', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('returns text when fetch is successful', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: jest.fn().mockResolvedValueOnce('package1\npackage2'),
    });
    const result = await fetchCompromisedPackages(URL);
    expect(result).toBe('package1\npackage2');
    expect(mockFetch).toHaveBeenCalledWith(URL);
  });

  it('returns null and warns if response is not ok', async () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    });
    const result = await fetchCompromisedPackages('https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/refs/heads/main/compro.txt');
    expect(result).toBeNull();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: Network error, status is : , 404, Not Found')
    );
    warnSpy.mockRestore();
  });

  it('returns null and warns if fetch throws', async () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    mockFetch.mockRejectedValueOnce(new Error('Warning: Failed to fetch compromised packages: fetch failed'));
    const result = await fetchCompromisedPackages('http://example.com/list.txt');
    expect(result).toBeNull();
    warnSpy.mockRestore();
  });
});
