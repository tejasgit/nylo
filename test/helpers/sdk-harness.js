/**
 * Minimal DOM stub harness that loads src/nylo.js into a vm sandbox so
 * consent transitions, storage deletion and fail-closed behavior can be
 * unit-tested in Node.
 */

'use strict';

const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');

const SDK_SOURCE = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'nylo.js'), 'utf8');

function makeStorage(seed) {
  const map = new Map(Object.entries(seed || {}));
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    removeItem: (k) => { map.delete(k); },
    _map: map
  };
}

function loadSdk(opts) {
  opts = opts || {};
  const attrs = Object.assign({ 'data-customer-id': '1' }, opts.attrs || {});

  const localStorage = makeStorage(opts.localStorageSeed);
  const sessionStorage = makeStorage(opts.sessionStorageSeed);
  const cookieJar = {};
  const fetchCalls = [];

  const documentStub = {
    readyState: 'complete',
    title: 'Test Page',
    referrer: '',
    hidden: false,
    currentScript: {
      getAttribute: (name) => (name in attrs ? attrs[name] : null)
    },
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => {},
    removeEventListener: () => {},
    get cookie() {
      return Object.entries(cookieJar).map(([k, v]) => k + '=' + v).join('; ');
    },
    set cookie(str) {
      const parts = String(str).split(';');
      const [key, ...valParts] = parts[0].split('=');
      const value = valParts.join('=');
      const maxAgeZero = parts.some((p) => p.trim() === 'max-age=0');
      if (maxAgeZero || value === '') {
        delete cookieJar[key.trim()];
      } else {
        cookieJar[key.trim()] = value;
      }
    }
  };

  // Optional gate to defer WebCrypto async work deterministically in tests:
  // pass opts.cryptoGate (a Promise); subtle operations await it first.
  var cryptoObj = webcrypto;
  if (opts.cryptoGate) {
    const gatedSubtle = {};
    for (const m of ['digest', 'importKey', 'sign', 'verify', 'encrypt', 'decrypt', 'deriveBits', 'deriveKey']) {
      gatedSubtle[m] = (...args) => opts.cryptoGate.then(() => webcrypto.subtle[m](...args));
    }
    cryptoObj = {
      getRandomValues: (arr) => webcrypto.getRandomValues(arr),
      randomUUID: () => webcrypto.randomUUID(),
      subtle: gatedSubtle
    };
  }

  const windowStub = {
    location: {
      hostname: opts.hostname || 'example.com',
      protocol: 'https:',
      href: 'https://' + (opts.hostname || 'example.com') + '/',
      pathname: '/',
      search: '',
      hash: opts.hash || '',
      origin: 'https://' + (opts.hostname || 'example.com')
    },
    crypto: cryptoObj,
    innerWidth: 1024,
    innerHeight: 768,
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => true,
    history: { replaceState: () => {} }
  };
  windowStub.window = windowStub;

  const timers = [];
  const sandbox = {
    window: windowStub,
    document: documentStub,
    localStorage,
    sessionStorage,
    navigator: { language: 'en-US', userAgent: 'nylo-test-harness' },
    screen: { width: 1024, height: 768 },
    crypto: cryptoObj,
    history: windowStub.history,
    performance: {
      now: () => Date.now(),
      mark: () => {},
      measure: () => {},
      getEntriesByName: () => [],
      timeOrigin: Date.now(),
      timing: null
    },
    fetch: (url, options) => {
      fetchCalls.push({ url, options });
      const handler = opts.fetchHandler;
      if (handler) return handler(url, options);
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ success: true }) });
    },
    console,
    setInterval: (fn, ms) => { timers.push(fn); return timers.length; },
    clearInterval: () => {},
    setTimeout,
    clearTimeout,
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    URLSearchParams,
    URL,
    TextEncoder,
    TextDecoder,
    Intl,
    CustomEvent: class CustomEventStub {
      constructor(type, init) {
        this.type = type;
        this.detail = init ? init.detail : undefined;
      }
    }
  };

  vm.createContext(sandbox);
  vm.runInContext(SDK_SOURCE, sandbox, { filename: 'nylo.js' });

  return {
    sandbox,
    window: windowStub,
    document: documentStub,
    localStorage,
    sessionStorage,
    cookieJar,
    fetchCalls,
    get Nylo() { return windowStub.Nylo; },
    flush: () => new Promise((resolve) => setTimeout(resolve, 25))
  };
}

module.exports = { loadSdk };
