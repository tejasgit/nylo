/**
 * SPDX-License-Identifier: LicenseRef-Nylo-Dual
 *
 * Nylo Analytics SDK v1.0.0
 * Privacy-first cross-domain analytics tracking
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Dual-licensed: core tracking under the MIT License (see LICENSE);
 * cross-domain identity modules (CrossDomainIdentity, WaiTag generation,
 * encrypted configuration parsing) under the Nylo Commercial License
 * (see COMMERCIAL-LICENSE). Commercial production use of the cross-domain
 * features requires a commercial license. See LICENSING.md for the boundary.
 *
 * @see https://github.com/tejasgit/nylo
 */
(function() {
  'use strict';

  var config = {
    version: '1.0.0',
    batchSize: 25,
    batchInterval: 12000,
    maxRetries: 3,
    compressionEnabled: true,
    performanceMonitoring: true,
    securityValidation: true,
    crossDomainEnabled: true,
    anonymousMode: false,
    allowQueryParamTokens: false
  };

  var state = {
    initialized: false,
    consent: 'unknown', // 'unknown' | 'granted' | 'denied' | 'withdrawn'
    trackingStarted: false,
    trackingEpoch: 0, // bumped on stop/withdrawal to cancel in-flight startup
    sessionId: null,
    userId: null,
    waiTag: null,
    eventQueue: [],
    retryQueue: [],
    performanceMetrics: {
      eventsProcessed: 0,
      batchesSent: 0,
      errors: 0,
      lastBatchTime: 0,
      crossDomainSyncs: 0,
      timings: {
        earlyCleanupDetected: false,
        earlyCleanupDurationMs: null,
        tokenDetectionTimestamp: null,
        tokenVerificationStartMs: null,
        tokenVerificationDurationMs: null,
        tokenVisibilityWindowMs: null,
        sdkInitDurationMs: null,
        urlCleanupDurationMs: null,
        tokenSource: null
      }
    },
    listeners: new Map(),
    batchTimer: null,
    retryTimer: null,
    crossDomainData: {
      referringDomain: null,
      tokenReceived: false,
      identitySynced: false
    }
  };

  var script = document.currentScript || document.querySelector('script[data-customer-id]');
  var customerId = script?.getAttribute('data-customer-id') || '1';
  var debugMode = script?.getAttribute('data-debug') === 'true';
  var embedId = script?.getAttribute('data-embed-id') || 'default';
  var encryptedConfig = script?.getAttribute('data-config') || null;
  var plainFeatures = script?.getAttribute('data-features') || null;
  var encryptedSecurity = script?.getAttribute('data-security') || null;
  var apiEndpoint = script?.getAttribute('data-api') || null;
  // Optional allowlist of query parameters (e.g. utm_source) the integrator
  // wants collected. Everything else in the query string never leaves the
  // browser — see sanitizeUrlForTransport().
  var allowedQueryParams = (script?.getAttribute('data-allowed-params') || '')
    .split(',')
    .map(function(s) { return s.trim(); })
    .filter(Boolean);

  var TrackingFeatures = {
    trackPageViews: false,
    trackLinks: false,
    trackButtons: false,
    trackForms: false,
    trackScrolling: false,
    trackHovers: false,
    trackClicks: false,
    trackErrors: false,
    trackCustomEvents: false,
    trackFileDownloads: false,
    trackExternalLinks: false,
    trackVideoInteractions: false,
    trackSearches: false,
    trackElementVisibility: false,
    trackPagePerformance: false,
    trackUserEngagement: false,
    trackConversions: false,
    trackCrossDomain: false,
    trackBounceRate: false,
    trackReturnVisitors: false,
    trackDeviceInfo: false,
    trackBrowserInfo: false,
    trackReferrerTracking: false
  };

  var Security = {
    sanitize: function(input) {
      if (typeof input !== 'string') return String(input || '');
      return input.replace(/[<>"'&]/g, function(char) {
        return {'<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;', '&': '&amp;'}[char];
      }).slice(0, 1000);
    },

    validateDomain: function(domain) {
      var domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
      return domainRegex.test(domain);
    },

    validateSessionId: function(sessionId) {
      return /^[a-zA-Z0-9_-]{10,50}$/.test(sessionId);
    },

    validateWaiTag: function(waiTag) {
      return /^wai_[0-9a-zA-Z]{10,}_[a-zA-Z0-9]{1,}$/.test(waiTag);
    },

    generateCSRFToken: function() {
      if (typeof crypto === 'undefined' || !crypto || !crypto.getRandomValues) {
        Logger.error('crypto.getRandomValues not available — cannot generate secure ID');
        return null;
      }
      return Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
    },

    generateSecureId: function(domain) {
      if (!window.crypto || !window.crypto.getRandomValues) {
        Logger.error('crypto.getRandomValues not available — cannot generate secure session ID');
        return null;
      }

      var randomBytes = new Uint8Array(16);
      window.crypto.getRandomValues(randomBytes);

      var randomHex = Array.from(randomBytes, function(byte) {
        return byte.toString(16).padStart(2, '0');
      }).join('');

      var domainHash = this.hashString(domain || 'default').substring(0, 8);
      return randomHex + '-' + domainHash;
    },

    /**
     * WaiTag Generation (Patent-Pending)
     * Generates a pseudonymous cross-domain identifier
     * Format: wai_<timestamp_base36>_<random><domain_hash>
     *
     * COMMERCIAL: This function is part of the cross-domain identity
     * system covered by COMMERCIAL-LICENSE.
     */
    generateWaiTag: function(domain) {
      if (!window.crypto || !window.crypto.getRandomValues) {
        Logger.error('crypto.getRandomValues not available — cannot generate secure WaiTag');
        return null;
      }

      var randomBytes = new Uint8Array(16);
      window.crypto.getRandomValues(randomBytes);

      var randomId = Array.from(randomBytes, function(byte) {
        return byte.toString(36).padStart(2, '0');
      }).join('').substring(0, 19);

      var domainHash = this.hashString(domain || 'default').substring(0, 8);
      return 'wai_' + randomId + '_' + domainHash;
    },

    hashString: function(str) {
      var hash = 0;
      for (var i = 0; i < str.length; i++) {
        var char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
      }
      return Math.abs(hash).toString(16);
    },

    generateIntegrityHash: function(sessionId, domain, waiTag) {
      return this.hashString(sessionId + ':' + domain + ':' + waiTag + ':' + customerId);
    },

    _hmacKeyPromise: null,

    /**
     * Storage-integrity HMAC — TAMPER-EVIDENCE, NOT AUTHENTICATION. The key
     * is derived from the public customer ID, so anyone who reads this file
     * can compute valid MACs. It catches accidental corruption and naive
     * cross-context injection into cookies/storage; it cannot stop a
     * deliberate attacker, and the server must never treat client-side
     * storage (or this MAC) as trusted input.
     */
    getHMACKey: function() {
      if (this._hmacKeyPromise) return this._hmacKeyPromise;
      var keyData = new TextEncoder().encode('nylo_integrity:' + customerId);
      this._hmacKeyPromise = window.crypto.subtle.importKey(
        'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
      );
      return this._hmacKeyPromise;
    },

    generateIntegrityHMAC: function(sessionId, domain, waiTag) {
      var data = sessionId + ':' + domain + ':' + waiTag + ':' + customerId;
      var encoded = new TextEncoder().encode(data);
      return this.getHMACKey().then(function(key) {
        return window.crypto.subtle.sign('HMAC', key, encoded);
      }).then(function(sig) {
        return Array.from(new Uint8Array(sig), function(b) {
          return b.toString(16).padStart(2, '0');
        }).join('');
      });
    },

    verifyIntegrityHMAC: function(sessionId, domain, waiTag, hmac) {
      if (!hmac || typeof hmac !== 'string' || hmac.length !== 64) return Promise.resolve(false);
      return this.generateIntegrityHMAC(sessionId, domain, waiTag).then(function(expected) {
        if (expected.length !== hmac.length) return false;
        var match = true;
        for (var i = 0; i < expected.length; i++) {
          if (expected[i] !== hmac[i]) match = false;
        }
        return match;
      }).catch(function() { return false; });
    }
  };

  var Performance = {
    mark: function(name) {
      if (config.performanceMonitoring && performance.mark) {
        performance.mark('nylo-' + name);
      }
    },

    measure: function(name, startMark) {
      if (config.performanceMonitoring && performance.measure) {
        try {
          performance.measure('nylo-' + name, 'nylo-' + startMark);
          var measures = performance.getEntriesByName('nylo-' + name);
          return measures[measures.length - 1]?.duration || 0;
        } catch (e) {
          return 0;
        }
      }
      return 0;
    },

    getMetrics: function() {
      return {
        eventsProcessed: state.performanceMetrics.eventsProcessed,
        batchesSent: state.performanceMetrics.batchesSent,
        errors: state.performanceMetrics.errors,
        lastBatchTime: state.performanceMetrics.lastBatchTime,
        crossDomainSyncs: state.performanceMetrics.crossDomainSyncs,
        memoryUsage: performance.memory ? {
          used: Math.round(performance.memory.usedJSHeapSize / 1024 / 1024),
          total: Math.round(performance.memory.totalJSHeapSize / 1024 / 1024)
        } : null,
        queueSize: state.eventQueue.length,
        retryQueueSize: state.retryQueue.length,
        timings: state.performanceMetrics.timings
      };
    },

    getTimingMetrics: function() {
      var t = state.performanceMetrics.timings;
      return {
        earlyCleanup: {
          detected: t.earlyCleanupDetected,
          durationMs: t.earlyCleanupDurationMs
        },
        tokenVerification: {
          durationMs: t.tokenVerificationDurationMs,
          source: t.tokenSource
        },
        tokenVisibilityWindowMs: t.tokenVisibilityWindowMs,
        tokenVisibilityWindowNote: t.earlyCleanupDetected
          ? 'Duration of early-cleanup script execution (token in hash for this long)'
          : 'Time from page load to SDK URL cleanup (token in hash for this long)',
        sdkInitDurationMs: t.sdkInitDurationMs,
        urlCleanupDurationMs: t.urlCleanupDurationMs,
        transport: {
          method: t.tokenSource === 'search' ? 'query_parameter' : 'hash_fragment',
          httpBytesLeaked: t.tokenSource === 'search' ? 'token_transmitted_in_http_request' : 0,
          loggingSurface: t.tokenSource === 'search' ? '6/6 standard HTTP log fields' : '0/6 standard HTTP log fields (structural guarantee per RFC 3986)'
        }
      };
    }
  };

  var ENVELOPE_SCHEMA_VERSION = 1;
  // Shared with shared/event-envelope.js — fields hoisted into the batch
  // envelope's `common` block when identical across events. Note: customerId
  // is part of the wire contract for legacy payloads, but this SDK no longer
  // emits it — tenant identity travels only inside the server-signed write
  // grant, never as a caller-asserted field.
  var ENVELOPE_COMMON_FIELDS = ['sessionId', 'userId', 'waiTag', 'domain', 'customerId'];
  var Compression = {
    compress: function(data) {
      var first = data[0] || {};
      var common = {};
      ENVELOPE_COMMON_FIELDS.forEach(function(field) {
        var value = first[field];
        if (value !== undefined && value !== null) common[field] = value;
      });

      if (!config.compressionEnabled) {
        return { common: common, events: data };
      }

      try {
        var compressed = data.map(function(event) {
          var rest = {};
          Object.keys(event).forEach(function(key) {
            if (ENVELOPE_COMMON_FIELDS.indexOf(key) !== -1 && event[key] === common[key]) return;
            rest[key] = event[key];
          });
          return rest;
        });
        return { common: common, events: compressed };
      } catch (e) {
        Logger.error('Compression failed:', e);
        return { common: common, events: data };
      }
    }
  };

  var Logger = {
    log: function(level) {
      if (!debugMode && level === 'debug') return;
      var args = Array.prototype.slice.call(arguments, 1);
      var prefix = '[Nylo v' + config.version + ']';
      if (level === 'error') {
        console.error.apply(console, [prefix].concat(args));
      } else {
        console.log.apply(console, [prefix].concat(args));
      }
    },
    debug: function() { this.log.apply(this, ['debug'].concat(Array.prototype.slice.call(arguments))); },
    info: function() { this.log.apply(this, ['info'].concat(Array.prototype.slice.call(arguments))); },
    warn: function() { this.log.apply(this, ['warn'].concat(Array.prototype.slice.call(arguments))); },
    error: function() { this.log.apply(this, ['error'].concat(Array.prototype.slice.call(arguments))); },
    performance: function(action, duration) {
      if (config.performanceMonitoring) {
        this.debug('Performance: ' + action + ' took ' + duration.toFixed(2) + 'ms');
      }
    }
  };

  /**
   * COMMERCIAL FEATURE: Cross-Domain Identity Management
   *
   * This module implements the WTX-1 protocol for cross-domain
   * identity preservation. Production use requires a commercial license.
   * See COMMERCIAL-LICENSE for details.
   */
  var CrossDomainIdentity = {
    checkForCrossDomainToken: function(isCancelled) {
      isCancelled = isCancelled || function() { return false; };
      var crossDomainToken = null;
      var tokenSource = null;
      var tokenDetectionTime = performance.now();

      if (window.__nylo_early_token) {
        crossDomainToken = window.__nylo_early_token;
        tokenSource = 'early_cleanup';
        delete window.__nylo_early_token;
      }

      if (!crossDomainToken) {
        var hash = window.location.hash;
        if (hash) {
          var hashParams = new URLSearchParams(hash.substring(1));
          crossDomainToken = hashParams.get('nylo_token') || hashParams.get('wai_token');
          if (crossDomainToken) tokenSource = 'hash';
        }
      }
      if (!crossDomainToken && config.allowQueryParamTokens) {
        var urlParams = new URLSearchParams(window.location.search);
        crossDomainToken = urlParams.get('nylo_token') || urlParams.get('wai_token');
        if (crossDomainToken) tokenSource = 'search';
      }

      if (crossDomainToken) {
        Logger.info('Cross-domain token detected via ' + tokenSource);
        state.crossDomainData.tokenReceived = true;
        state.performanceMetrics.timings.tokenDetectionTimestamp = tokenDetectionTime;
        state.performanceMetrics.timings.tokenSource = tokenSource;

        if (window.__nylo_early_token_timing) {
          state.performanceMetrics.timings.earlyCleanupDetected = true;
          state.performanceMetrics.timings.earlyCleanupDurationMs = window.__nylo_early_token_timing.duration;
          state.performanceMetrics.timings.tokenVisibilityWindowMs = window.__nylo_early_token_timing.duration;
          Logger.debug('Early-cleanup timing: ' + state.performanceMetrics.timings.earlyCleanupDurationMs.toFixed(3) + 'ms');
          delete window.__nylo_early_token_timing;
        }

        try {
          state.crossDomainData.referringDomain = document.referrer ? new URL(document.referrer).hostname : null;
        } catch (e) {
          state.crossDomainData.referringDomain = null;
        }

        if (tokenSource === 'early_cleanup') {
          Logger.debug('Token already cleaned by early-cleanup script');
        } else {
          try {
            var cleanupStart = performance.now();
            if (tokenSource === 'hash') {
              var currentHash = window.location.hash;
              var cleanHash = currentHash.substring(1).split('&').filter(function(p) {
                return !p.startsWith('nylo_token=') && !p.startsWith('wai_token=');
              }).join('&');
              var newHash = cleanHash ? '#' + cleanHash : '';
              history.replaceState(null, '', window.location.pathname + window.location.search + newHash);
            } else if (tokenSource === 'search') {
              var cleanParams = new URLSearchParams(window.location.search);
              cleanParams.delete('nylo_token');
              cleanParams.delete('wai_token');
              var newSearch = cleanParams.toString() ? '?' + cleanParams.toString() : '';
              history.replaceState(null, '', window.location.pathname + newSearch + window.location.hash);
            }
            var cleanupEnd = performance.now();
            state.performanceMetrics.timings.urlCleanupDurationMs = cleanupEnd - cleanupStart;
            state.performanceMetrics.timings.tokenVisibilityWindowMs = cleanupEnd;
            Logger.debug('Cross-domain token cleaned from URL (' + state.performanceMetrics.timings.urlCleanupDurationMs.toFixed(3) + 'ms, visibility window: ' + cleanupEnd.toFixed(1) + 'ms from page load)');
          } catch (e) {
            Logger.debug('Could not clean token from URL');
          }
        }

        return this.verifyAndProcessToken(crossDomainToken, isCancelled);
      }

      return Promise.resolve(false);
    },

    verifyAndProcessToken: function(token, isCancelled) {
      isCancelled = isCancelled || function() { return false; };
      var self = this;
      var domain = window.location.hostname;
      var verificationStartTime = performance.now();
      state.performanceMetrics.timings.tokenVerificationStartMs = verificationStartTime;

      // Verification requires a write grant: the server must not let an
      // unauthenticated caller consume (and thereby void) someone's token.
      // The body carries only the token and this page's domain — tenant
      // identity comes from the grant, and the referrer is not sent.
      return WriteGrant.get().then(function(grant) {
        if (isCancelled()) return false;
        var headers = { 'Content-Type': 'application/json' };
        if (grant) headers['X-Nylo-Grant'] = grant;
        return trackedFetch(getApiUrl() + '/api/tracking/verify-cross-domain-token', {
          method: 'POST',
          headers: headers,
          credentials: 'include',
          body: JSON.stringify({
            token: token,
            domain: domain
          })
        })
      .then(function(response) {
        if (!response.ok) throw new Error('Verification failed');
        return response.json();
      })
      .then(function(result) {
        if (isCancelled()) return false; // startup epoch superseded — discard
        var verificationEndTime = performance.now();
        state.performanceMetrics.timings.tokenVerificationDurationMs = verificationEndTime - verificationStartTime;
        Logger.debug('Token verification duration: ' + state.performanceMetrics.timings.tokenVerificationDurationMs.toFixed(3) + 'ms');

        if (result.success && result.identity) {
          state.sessionId = result.identity.sessionId;
          state.waiTag = result.identity.waiTag;
          state.userId = result.identity.userId;
          state.crossDomainData.identitySynced = true;
          state.performanceMetrics.crossDomainSyncs++;

          Security.generateIntegrityHMAC(state.sessionId, domain, state.waiTag)
            .then(function(hmac) {
              if (isCancelled()) return;
              self.storeIdentityData({
                sessionId: state.sessionId,
                waiTag: state.waiTag,
                userId: state.userId,
                domain: domain,
                syncedAt: new Date().toISOString(),
                integrity: hmac
              });
            })
            .catch(function() {
              if (isCancelled()) return;
              Logger.error('HMAC generation failed during cross-domain sync — storing without integrity');
              self.storeIdentityData({
                sessionId: state.sessionId,
                waiTag: state.waiTag,
                userId: state.userId,
                domain: domain,
                syncedAt: new Date().toISOString(),
                integrity: null
              });
            });

          self.trackCrossDomainEvent('cross_domain_arrival', {
            referringDomain: state.crossDomainData.referringDomain,
            tokenVerified: true,
            identityPreserved: true,
            timings: state.performanceMetrics.timings
          });

          Logger.info('Cross-domain identity synchronized');
          return true;
        }
        return false;
      })
      .catch(function(error) {
        state.performanceMetrics.timings.tokenVerificationDurationMs = performance.now() - verificationStartTime;
        Logger.error('Cross-domain token verification failed:', error);
        return false;
      });
      });
    },

    generateNewIdentity: function(isCancelled) {
      isCancelled = isCancelled || function() { return false; };
      var self = this;
      var domain = window.location.hostname;

      if (isCancelled()) return Promise.resolve();

      state.sessionId = Security.generateSecureId(domain);
      state.waiTag = Security.generateWaiTag(domain);

      if (!state.sessionId || !state.waiTag) {
        // Fail closed: without Web Crypto there are no unpredictable
        // identifiers. A timestamp-derived fallback would be a guessable
        // identity, so no identity is created and tracking does not start.
        Logger.error('Secure randomness unavailable - tracking disabled (no predictable fallback identity)');
        state.sessionId = null;
        state.waiTag = null;
        state.trackingStarted = false;
        return Promise.reject({ nyloAborted: 'crypto_unavailable' });
      }

      return Security.generateIntegrityHMAC(state.sessionId, domain, state.waiTag)
        .then(function(hmac) {
          if (isCancelled()) return; // superseded — never persist or register stale identity
          var identityData = {
            sessionId: state.sessionId,
            waiTag: state.waiTag,
            userId: state.userId,
            domain: domain,
            createdAt: new Date().toISOString(),
            integrity: hmac
          };

          self.storeIdentityData(identityData);
          self.registerIdentityWithServer(identityData);
          Logger.info('New identity generated:', state.waiTag);
        })
        .catch(function() {
          if (isCancelled()) return;
          Logger.error('HMAC generation failed — identity stored without integrity (will be rejected on next read if crypto becomes available)');
          var identityData = {
            sessionId: state.sessionId,
            waiTag: state.waiTag,
            userId: state.userId,
            domain: domain,
            createdAt: new Date().toISOString(),
            integrity: null
          };
          self.storeIdentityData(identityData);
          self.registerIdentityWithServer(identityData);
        });
    },

    storeIdentityData: function(identityData) {
      if (state.consent !== 'granted') {
        Logger.debug('Consent not granted - identity will not be persisted');
        return;
      }
      try {
        var cookieData = btoa(JSON.stringify(identityData));
        var cookieFlags = 'path=/; SameSite=Strict; max-age=86400';
        if (window.location.protocol === 'https:') {
          cookieFlags += '; Secure';
        }
        document.cookie = 'nylo_wai=' + cookieData + '; ' + cookieFlags;
      } catch (e) {
        Logger.debug('Cookie storage failed');
      }

      try {
        var encodedData = this.encodeIdentityForStorage(identityData);
        localStorage.setItem('nylo_cross_domain_identity', encodedData);
      } catch (e) {
        Logger.debug('localStorage not available');
      }

      try {
        sessionStorage.setItem('nylo_session_identity', JSON.stringify(identityData));
      } catch (e) {
        Logger.debug('sessionStorage not available');
      }
    },

    _readRawStoredData: function() {
      var candidates = [];

      try {
        var cookies = document.cookie.split(';');
        var waiCookie = cookies.find(function(c) { return c.trim().startsWith('nylo_wai='); });
        if (waiCookie) {
          var cookieData = waiCookie.split('=')[1];
          candidates.push({ source: 'cookie', data: JSON.parse(atob(cookieData)) });
        }
      } catch (e) {}

      try {
        var storedData = localStorage.getItem('nylo_cross_domain_identity');
        if (storedData) {
          var decoded = this.decodeIdentityFromStorage(storedData);
          if (decoded) candidates.push({ source: 'localStorage', data: decoded });
        }
      } catch (e) {}

      try {
        var sessionData = sessionStorage.getItem('nylo_session_identity');
        if (sessionData) candidates.push({ source: 'sessionStorage', data: JSON.parse(sessionData) });
      } catch (e) {}

      return candidates;
    },

    _clearStorageLayer: function(source) {
      try {
        if (source === 'cookie') {
          document.cookie = 'nylo_wai=; path=/; max-age=0';
        } else if (source === 'localStorage') {
          localStorage.removeItem('nylo_cross_domain_identity');
        } else if (source === 'sessionStorage') {
          sessionStorage.removeItem('nylo_session_identity');
        }
      } catch (e) {}
    },

    getStoredIdentityData: function() {
      var self = this;
      var candidates = this._readRawStoredData();

      if (candidates.length === 0) return Promise.resolve(null);

      var verificationChain = Promise.resolve(null);

      candidates.forEach(function(candidate) {
        verificationChain = verificationChain.then(function(verified) {
          if (verified) return verified;

          var d = candidate.data;
          if (!d || !d.sessionId || !d.waiTag) {
            self._clearStorageLayer(candidate.source);
            return null;
          }

          if (d.integrity && typeof d.integrity === 'string' && d.integrity.length === 64) {
            return Security.verifyIntegrityHMAC(d.sessionId, d.domain || '', d.waiTag, d.integrity)
              .then(function(valid) {
                if (valid) return d;
                Logger.debug('Integrity check failed for ' + candidate.source + ' — clearing');
                self._clearStorageLayer(candidate.source);
                return null;
              });
          }

          var legacyExpected = Security.generateIntegrityHash(d.sessionId, d.domain || '', d.waiTag);
          if (d.integrity === legacyExpected) {
            return Security.generateIntegrityHMAC(d.sessionId, d.domain || '', d.waiTag)
              .then(function(hmac) {
                d.integrity = hmac;
                self.storeIdentityData(d);
                Logger.debug('Migrated legacy integrity hash to HMAC for ' + candidate.source);
                return d;
              })
              .catch(function() {
                Logger.error('HMAC migration failed for legacy integrity — rejecting');
                self._clearStorageLayer(candidate.source);
                return null;
              });
          }

          Logger.debug('Invalid integrity for ' + candidate.source + ' — clearing');
          self._clearStorageLayer(candidate.source);
          return null;
        });
      });

      return verificationChain;
    },

    registerIdentityWithServer: function(identityData) {
      if (state.consent !== 'granted') return; // never register after withdrawal
      // Registration carries only the pseudonymous identifier and its
      // domain binding. No customer ID (tenant comes from the grant), no
      // user agent, and no other browser telemetry.
      WriteGrant.get().then(function(grant) {
        if (state.consent !== 'granted') return;
        if (!grant) {
          Logger.debug('No write grant - skipping identity registration');
          return;
        }
        return trackedFetch(getApiUrl() + '/api/tracking/register-waitag', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Nylo-Grant': grant },
          credentials: 'include',
          body: JSON.stringify({
            waiTag: identityData.waiTag,
            sessionId: identityData.sessionId,
            domain: identityData.domain,
            timestamp: identityData.createdAt
          })
        });
      }).catch(function() {});
    },

    /**
     * NOT ENCRYPTION. This is reversible base64 encoding with a trailer
     * check — anyone with devtools can decode it. Its only purpose is to
     * detect accidental corruption and keep casual eyes off the payload;
     * confidentiality is provided by the browser's storage isolation, not
     * by this encoding. (Renamed from "encryptIdentityData", which
     * overstated what it does.)
     */
    encodeIdentityForStorage: function(data) {
      var jsonStr = JSON.stringify(data);
      var timestamp = Date.now().toString(36);
      var trailer = customerId + timestamp;
      var encoded = btoa(jsonStr + trailer);
      return encoded + '.' + timestamp;
    },

    decodeIdentityFromStorage: function(encodedStr) {
      try {
        var parts = encodedStr.split('.');
        if (parts.length !== 2) return null;
        var encoded = parts[0];
        var timestamp = parts[1];
        var trailer = customerId + timestamp;
        var decoded = atob(encoded);
        if (!decoded.endsWith(trailer)) return null;
        var jsonStr = decoded.substring(0, decoded.length - trailer.length);
        return JSON.parse(jsonStr);
      } catch (e) {
        return null;
      }
    },

    trackCrossDomainEvent: function(eventType, eventData) {
      var crossDomainEventData = Object.assign({}, eventData, {
        crossDomainContext: {
          waiTag: state.waiTag,
          referringDomain: state.crossDomainData.referringDomain,
          identitySynced: state.crossDomainData.identitySynced,
          tokenReceived: state.crossDomainData.tokenReceived
        }
      });
      queueEvent(eventType, crossDomainEventData);
    }
  };

  /**
   * COMMERCIAL FEATURE: Encrypted Configuration
   *
   * Dashboard-controlled tracking via AES-GCM encrypted config.
   * See COMMERCIAL-LICENSE for details.
   */
  function disableAllFeatures() {
    Object.keys(TrackingFeatures).forEach(function(feature) {
      TrackingFeatures[feature] = false;
    });
  }

  /**
   * Fail-closed configuration: tracking features are only enabled when
   * valid configuration is present. Missing or undecryptable config
   * leaves every feature disabled.
   */
  function parseEncryptedConfig(encConfig, custId) {
    disableAllFeatures();

    if (!encConfig) {
      if (plainFeatures) {
        plainFeatures.split(',').forEach(function(feature) {
          feature = feature.trim();
          if (TrackingFeatures.hasOwnProperty(feature)) {
            TrackingFeatures[feature] = true;
          }
        });
      } else {
        Logger.info('No tracking configuration provided (data-config or data-features) - all tracking disabled (fail closed)');
      }
      return Promise.resolve(TrackingFeatures);
    }

    return deriveKey(custId)
      .then(function(key) { return decryptConfig(encConfig, key); })
      .then(function(decryptedData) {
        var cfg = JSON.parse(decryptedData);

        disableAllFeatures();

        if (cfg.features && Array.isArray(cfg.features)) {
          cfg.features.forEach(function(feature) {
            if (TrackingFeatures.hasOwnProperty(feature)) {
              TrackingFeatures[feature] = true;
            }
          });
        }

        if (cfg.privacy) {
          state.privacySettings = cfg.privacy;
        }

        return TrackingFeatures;
      })
      .catch(function() {
        disableAllFeatures();
        Logger.error('Encrypted configuration could not be decrypted - all tracking disabled (fail closed)');
        return TrackingFeatures;
      });
  }

  function deriveKey(custId) {
    if (!window.crypto || !window.crypto.subtle) {
      Logger.error('Web Crypto API not available — encrypted config cannot be decrypted');
      return Promise.reject(new Error('Web Crypto API required for encrypted configuration'));
    }

    var encoder = new TextEncoder();
    var data = encoder.encode('nylo_v1:' + custId + ':' + window.location.hostname);

    return window.crypto.subtle.digest('SHA-256', data)
      .then(function(hashBuffer) { return new Uint8Array(hashBuffer); });
  }

  function decryptConfig(encConfig, key) {
    if (!window.crypto || !window.crypto.subtle) {
      Logger.error('Web Crypto API not available — cannot decrypt configuration securely');
      return Promise.reject(new Error('Web Crypto API required for decryption'));
    }

    try {
      var parts = encConfig.split('.');
      if (parts.length !== 2) throw new Error('Invalid format');

      var iv = new Uint8Array(atob(parts[0]).split('').map(function(c) { return c.charCodeAt(0); }));
      var encrypted = new Uint8Array(atob(parts[1]).split('').map(function(c) { return c.charCodeAt(0); }));

      return window.crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt'])
        .then(function(cryptoKey) {
          return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, encrypted);
        })
        .then(function(decrypted) {
          return new TextDecoder().decode(decrypted);
        });
    } catch (error) {
      return Promise.reject(new Error('Decryption failed: invalid encrypted config format'));
    }
  }

  function validateDomainAuthorization(encSecurity) {
    try {
      var securityData = JSON.parse(atob(encSecurity));
      var currentDomain = window.location.hostname;

      if (securityData.authorizedDomains && Array.isArray(securityData.authorizedDomains)) {
        var isAuthorized = securityData.authorizedDomains.some(function(domain) {
          if (domain.startsWith('*.')) {
            var baseDomain = domain.substring(2);
            if (!baseDomain) return false;
            // Exact host-boundary match: matches the base domain itself or
            // a true subdomain, never a lookalike suffix (evilexample.com).
            return currentDomain === baseDomain || currentDomain.endsWith('.' + baseDomain);
          }
          return domain === currentDomain;
        });

        Logger.info(isAuthorized ? 'Domain authorized' : 'Domain not authorized');
        return isAuthorized;
      }

      return true;
    } catch (error) {
      Logger.error('Domain authorization validation failed:', error);
      return false;
    }
  }

  function getApiUrl() {
    if (apiEndpoint) return apiEndpoint;

    try {
      var scripts = document.querySelectorAll('script[src*="nylo"]');
      if (scripts.length > 0) {
        var scriptSrc = scripts[0].src;
        return scriptSrc.split('/').slice(0, 3).join('/');
      }
    } catch (e) {}

    return window.location.origin;
  }

  // ---- Outbound request infrastructure ---------------------------------

  var inflightControllers = [];

  /**
   * Every network request the SDK makes goes through trackedFetch, which
   * registers an AbortController for it. Consent withdrawal must stop
   * requests that are already on the wire — not merely prevent new ones —
   * so abortInflightRequests() is called from stopTracking().
   */
  function trackedFetch(url, options) {
    options = options || {};
    var controller = null;
    if (typeof AbortController !== 'undefined') {
      controller = new AbortController();
      options.signal = controller.signal;
      inflightControllers.push(controller);
    }
    function settle() {
      if (!controller) return;
      var idx = inflightControllers.indexOf(controller);
      if (idx !== -1) inflightControllers.splice(idx, 1);
    }
    var request;
    try {
      request = fetch(url, options);
    } catch (e) {
      settle();
      return Promise.reject(e);
    }
    return request.then(
      function(response) { settle(); return response; },
      function(error) { settle(); throw error; }
    );
  }

  function abortInflightRequests() {
    var controllers = inflightControllers.splice(0, inflightControllers.length);
    controllers.forEach(function(controller) {
      try { controller.abort(); } catch (e) {}
    });
  }

  /**
   * Reduces a URL to origin + path before it leaves the browser. Query
   * strings and fragments routinely carry tokens, emails and search terms,
   * so they are stripped structurally (never pattern-filtered). Integrators
   * who need specific campaign parameters allowlist them via
   * data-allowed-params; those are collected individually, never as the raw
   * query string.
   */
  function sanitizeUrlForTransport(rawUrl) {
    if (!rawUrl) return '';
    try {
      var parsed = new URL(rawUrl);
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
      return parsed.origin + parsed.pathname;
    } catch (e) {
      return '';
    }
  }

  function collectAllowedQueryParams(rawUrl) {
    if (!allowedQueryParams.length || !rawUrl) return null;
    try {
      var parsed = new URL(rawUrl);
      var collected = null;
      allowedQueryParams.forEach(function(name) {
        var value = parsed.searchParams.get(name);
        if (value !== null) {
          collected = collected || {};
          collected[name] = String(value).substring(0, 200);
        }
      });
      return collected;
    } catch (e) {
      return null;
    }
  }

  // Custom-event metadata is developer-supplied, so it gets the same
  // structural minimization as SDK-built fields BEFORE serialization:
  // fingerprint-capable keys are dropped (semantic matching — aliases and
  // separator variants included) and URL string values are reduced to
  // origin + path. The server strips again as defense in depth, but the
  // browser must never send these in the first place.
  var FORBIDDEN_METADATA_EXACT = [
    'ua', 'dnt', 'language', 'languages', 'locale', 'platform', 'fonts',
    'plugins', 'mimetypes', 'battery', 'downlink', 'capabilities',
    'clickx', 'clicky', 'pagex', 'pagey', 'screenx', 'screeny',
    'clientx', 'clienty', 'offsetx', 'offsety', 'mousex', 'mousey',
    'cursorx', 'cursory', 'touchx', 'touchy', 'coordx', 'coordy',
    'xcoord', 'ycoord'
  ];
  var FORBIDDEN_METADATA_STEMS = [
    'useragent', 'uastring', 'fingerprint', 'timezone', 'viewport',
    'colordepth', 'pixeldepth', 'pixelratio', 'devicepixel',
    'hardwareconcurrency', 'devicememory', 'maxtouchpoints', 'touchsupport',
    'oscpu', 'cpuclass', 'mimetype', 'webgl', 'capabilit',
    'screenwidth', 'screenheight', 'screensize', 'screenres', 'screendepth',
    'availwidth', 'availheight', 'connectiontype', 'cookiesenabled',
    'donottrack'
  ];

  function isForbiddenMetadataKey(key) {
    var norm = String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!norm) return false;
    if (FORBIDDEN_METADATA_EXACT.indexOf(norm) !== -1) return true;
    for (var i = 0; i < FORBIDDEN_METADATA_STEMS.length; i++) {
      if (norm.indexOf(FORBIDDEN_METADATA_STEMS[i]) !== -1) return true;
    }
    return false;
  }

  function sanitizeMetadataForTransport(value, depth) {
    depth = depth || 0;
    if (depth > 6 || value === null || value === undefined) return value;
    if (typeof value === 'string') {
      if (/^https?:\/\//i.test(value.trim())) return sanitizeUrlForTransport(value);
      return value;
    }
    if (Object.prototype.toString.call(value) === '[object Array]') {
      var arr = [];
      for (var i = 0; i < value.length; i++) {
        arr.push(sanitizeMetadataForTransport(value[i], depth + 1));
      }
      return arr;
    }
    if (typeof value === 'object') {
      var out = {};
      for (var key in value) {
        if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
        if (isForbiddenMetadataKey(key)) continue;
        out[key] = sanitizeMetadataForTransport(value[key], depth + 1);
      }
      return out;
    }
    return value;
  }

  /**
   * Server-signed write grant. Before any data write, the SDK asks the
   * server for a short-lived grant for THIS page's domain; the server
   * resolves which tenant that domain belongs to from its own
   * configuration. The SDK never asserts tenant identity (no customer IDs
   * in bodies or headers), and every ingestion request carries the grant
   * in the X-Nylo-Grant header.
   */
  var WriteGrant = {
    value: null,
    expiresAtMs: 0,
    pending: null,

    get: function() {
      if (state.consent !== 'granted') return Promise.resolve(null);
      if (this.value && Date.now() < this.expiresAtMs - 30000) {
        return Promise.resolve(this.value);
      }
      if (this.pending) return this.pending;
      var self = this;
      this.pending = trackedFetch(getApiUrl() + '/api/tracking/grant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ domain: window.location.hostname })
      })
        .then(function(response) {
          if (!response.ok) throw new Error('grant request failed: HTTP ' + response.status);
          return response.json();
        })
        .then(function(result) {
          self.pending = null;
          if (result && result.success && result.grant) {
            self.value = result.grant;
            var parsedExpiry = result.expiresAt ? Date.parse(result.expiresAt) : NaN;
            self.expiresAtMs = isNaN(parsedExpiry) ? Date.now() + 5 * 60 * 1000 : parsedExpiry;
            return self.value;
          }
          return null;
        })
        .catch(function(error) {
          self.pending = null;
          Logger.debug('Write grant unavailable:', error && error.message);
          return null;
        });
      return this.pending;
    },

    invalidate: function() {
      this.value = null;
      this.expiresAtMs = 0;
      this.pending = null;
    }
  };

  function createEvent(eventType, metadata) {
    metadata = metadata || {};
    Performance.mark('create-event-start');

    if (!eventType || typeof eventType !== 'string') {
      Logger.error('Invalid event type provided');
      return null;
    }

    var featureMap = {
      'page_view': 'trackPageViews',
      'link_click': 'trackLinks',
      'button_click': 'trackButtons',
      'form_submit': 'trackForms',
      'scroll': 'trackScrolling',
      'hover': 'trackHovers',
      'click': 'trackClicks',
      'error': 'trackErrors',
      'custom': 'trackCustomEvents',
      'file_download': 'trackFileDownloads',
      'outbound_click': 'trackExternalLinks',
      'video_interaction': 'trackVideoInteractions',
      'search': 'trackSearches',
      'element_visible': 'trackElementVisibility',
      'performance': 'trackPagePerformance',
      'user_engagement': 'trackUserEngagement',
      'conversion': 'trackConversions',
      'cross_domain': 'trackCrossDomain',
      'bounce_rate': 'trackBounceRate',
      'return_visitor': 'trackReturnVisitors',
      'device_info': 'trackDeviceInfo',
      'browser_info': 'trackBrowserInfo',
      'referrer': 'trackReferrerTracking'
    };

    var featureKey = featureMap[eventType];
    if (featureKey && !TrackingFeatures[featureKey]) {
      return null;
    }

    var domain = window.location.hostname;

    // Event IDs must be unpredictable (they drive server-side dedup). If
    // secure randomness is unavailable the event is dropped — never given
    // a guessable ID.
    var eventId = Security.generateCSRFToken();
    if (!eventId) return null;

    // Data minimization is structural, not a filter: the event object is
    // built without fingerprint-capable fields. No user agent, language,
    // timezone, screen/viewport geometry, or browser capabilities — those
    // combine into a device fingerprint that would undermine the
    // consent-based identity model. Domain splitting (registrable domain vs
    // subdomain) is the server's job, using a real public-suffix list.
    var event = {
      eventId: eventId,
      sessionId: state.sessionId,
      waiTag: state.waiTag,
      userId: state.userId,
      embedId: embedId,
      timestamp: new Date().toISOString(),
      eventType: eventType,
      domain: domain,
      url: sanitizeUrlForTransport(window.location.href),
      path: window.location.pathname,
      title: document.title,
      referrer: sanitizeUrlForTransport(document.referrer),
      metadata: Security.sanitize(JSON.stringify(sanitizeMetadataForTransport(metadata))),
      crossDomainContext: state.crossDomainData.identitySynced ? {
        referringDomain: state.crossDomainData.referringDomain,
        identityPreserved: true,
        syncMethod: 'token_verification'
      } : null
    };

    var campaignParams = collectAllowedQueryParams(window.location.href);
    if (campaignParams) event.campaignParams = campaignParams;

    Performance.measure('create-event', 'create-event-start');
    state.performanceMetrics.eventsProcessed++;

    return event;
  }

  function queueEvent(eventType, metadata) {
    if (state.consent !== 'granted') return;
    var event = createEvent(eventType, metadata);
    if (!event) return;

    state.eventQueue.push(event);

    if (state.eventQueue.length >= config.batchSize * 3) {
      sendBatch();
    }
  }

  var Tracking = {
    pageView: function(additionalData) {
      if (!TrackingFeatures.trackPageViews) return;
      var pageData = Object.assign({
        loadTime: performance.timing ? performance.timing.loadEventEnd - performance.timing.navigationStart : 0
      }, additionalData || {});
      queueEvent('page_view', pageData);
    },

    click: function(target, additionalData) {
      if (!TrackingFeatures.trackClicks) return;
      var clickData = Object.assign({
        elementTag: target.tagName,
        elementId: target.id,
        elementClass: target.className,
        elementText: target.textContent?.substring(0, 100)
      }, additionalData || {});
      queueEvent('click', clickData);
    },

    customEvent: function(eventName, eventData) {
      if (!TrackingFeatures.trackCustomEvents) return;
      queueEvent('custom', {
        customEventName: eventName,
        customEventData: eventData || {}
      });
    },

    conversion: function(conversionType, value, additionalData) {
      if (!TrackingFeatures.trackConversions) return;
      queueEvent('conversion', Object.assign({
        conversionType: conversionType,
        conversionValue: value || null
      }, additionalData || {}));
    },

    error: function(error, context) {
      if (!TrackingFeatures.trackErrors) return;
      queueEvent('error', {
        errorMessage: String(error.message || error).substring(0, 500),
        errorStack: error.stack ? String(error.stack).substring(0, 1000) : undefined,
        errorContext: context || {}
      });
    }
  };

  var retryCount = 0;
  var isCircuitBreakerOpen = false;
  var pendingRetryTimers = new Set();

  function clearPendingRetries() {
    pendingRetryTimers.forEach(function(timerId) {
      try { clearTimeout(timerId); } catch (e) {}
    });
    pendingRetryTimers.clear();
    retryCount = 0;
    isCircuitBreakerOpen = false;
  }

  function sendBatch() {
    if (state.consent !== 'granted') return;
    if (state.eventQueue.length === 0) return;
    if (isCircuitBreakerOpen) return;

    Performance.mark('batch-start');
    var batch = state.eventQueue.splice(0, config.batchSize);
    var compressedBatch = Compression.compress(batch);

    // Identity travels in the signed body/envelope only. The headers carry
    // no session, tenant or identity values — the write grant authorizes
    // the request and the server derives the tenant from it.
    var body = JSON.stringify({
      schemaVersion: ENVELOPE_SCHEMA_VERSION,
      batchId: Security.generateCSRFToken(),
      sentAt: new Date().toISOString(),
      common: compressedBatch.common,
      events: compressedBatch.events
    });

    function scheduleRetry(eventsToRetry) {
      // After withdrawal the queues were purged; a late network failure
      // must not resurrect events into them.
      if (state.consent !== 'granted') return;
      state.performanceMetrics.errors++;

      if (retryCount < config.maxRetries) {
        state.retryQueue.push.apply(state.retryQueue, eventsToRetry);
        var retryDelay = Math.pow(2, retryCount) * 1000;
        retryCount++;

        var timerId = setTimeout(function() {
          pendingRetryTimers.delete(timerId);
          var retryBatch = state.retryQueue.splice(0, config.batchSize);
          if (retryBatch.length > 0) {
            state.eventQueue.unshift.apply(state.eventQueue, retryBatch);
            sendBatch();
          }
        }, retryDelay);
        pendingRetryTimers.add(timerId);
      } else {
        isCircuitBreakerOpen = true;
        var breakerId = setTimeout(function() {
          pendingRetryTimers.delete(breakerId);
          isCircuitBreakerOpen = false;
          retryCount = 0;
        }, 30000);
        pendingRetryTimers.add(breakerId);
      }
    }

    WriteGrant.get().then(function(grant) {
      if (state.consent !== 'granted') return;
      if (!grant) {
        Logger.warn('No write grant available - batch will be retried');
        scheduleRetry(batch);
        return;
      }

      return trackedFetch(getApiUrl() + '/api/track', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Nylo-Grant': grant,
          'X-Batch-Size': batch.length.toString(),
          'X-SDK-Version': config.version
        },
        credentials: 'include',
        body: body
      })
      .then(function(response) {
        if (!response.ok) {
          // An expired or revoked grant must not poison every retry:
          // drop the cached grant so the next attempt fetches a fresh one.
          if (response.status === 401 || response.status === 403) {
            WriteGrant.invalidate();
          }
          throw new Error('HTTP ' + response.status);
        }
        return response.json();
      })
      .then(function(result) {
        // Inspect per-event ingestion results; HTTP 200 alone is not success.
        // Events the server failed to store transiently are requeued with the
        // same eventId (server dedup makes redelivery idempotent). Events the
        // server rejected as invalid are dropped — retrying cannot fix them.
        var failedEvents = [];
        var rejectedCount = 0;
        if (result && Array.isArray(result.results)) {
          result.results.forEach(function(r) {
            if (!r || typeof r.index !== 'number' || !batch[r.index]) return;
            if (r.status === 'error') {
              failedEvents.push(batch[r.index]);
            } else if (r.status === 'rejected') {
              rejectedCount++;
            }
          });
        }

        if (rejectedCount > 0) {
          Logger.warn('Server rejected ' + rejectedCount + ' event(s) as invalid; dropping');
        }

        if (failedEvents.length > 0) {
          Logger.warn('Server failed to store ' + failedEvents.length + ' event(s); retrying');
          scheduleRetry(failedEvents);
          return;
        }

        retryCount = 0;
        isCircuitBreakerOpen = false;
        state.performanceMetrics.batchesSent++;
        state.performanceMetrics.lastBatchTime = Date.now();
        Performance.measure('batch-send', 'batch-start');
      })
      .catch(function() {
        scheduleRetry(batch);
      });
    });
  }

  function setupEventListeners() {
    var clickHandler = function(e) {
      if (!TrackingFeatures.trackClicks) return;
      var target = e.target.closest('a, button, [role="button"], input[type="submit"]');
      if (target) {
        // No pointer coordinates: element identity is analytics, exact
        // click positions are behavioral biometrics.
        Tracking.click(target, {
          timestamp: Date.now()
        });
      }
    };
    document.addEventListener('click', clickHandler, true);
    state.listeners.set('click', clickHandler);

    var formHandler = function(e) {
      if (!TrackingFeatures.trackForms) return;
      queueEvent('form_submit', {
        formId: e.target.id,
        formAction: sanitizeUrlForTransport(e.target.action),
        formMethod: e.target.method,
        fieldCount: e.target.elements.length
      });
    };
    document.addEventListener('submit', formHandler);
    state.listeners.set('submit', formHandler);

    var errorHandler = function(e) {
      Tracking.error(e.error || new Error(e.message), {
        filename: sanitizeUrlForTransport(e.filename),
        lineno: e.lineno,
        colno: e.colno
      });
    };
    window.addEventListener('error', errorHandler);
    state.listeners.set('error', errorHandler);

    var rejectionHandler = function(e) {
      Tracking.error(new Error('Unhandled Promise Rejection: ' + e.reason), {
        type: 'unhandled_promise_rejection'
      });
    };
    window.addEventListener('unhandledrejection', rejectionHandler);
    state.listeners.set('unhandledrejection', rejectionHandler);
  }

  function setupPageLifecycle() {
    var unloadHandler = function() {
      if (state.eventQueue.length > 0) sendBatch();
    };
    window.addEventListener('beforeunload', unloadHandler);
    state.listeners.set('beforeunload', unloadHandler);

    var visibilityHandler = function() {
      if (document.hidden && state.eventQueue.length > 0) sendBatch();
    };
    document.addEventListener('visibilitychange', visibilityHandler);
    state.listeners.set('visibilitychange', visibilityHandler);
  }

  /**
   * Consent state machine: 'unknown' -> 'granted' | 'denied',
   * 'granted' -> 'withdrawn'. Default is NOT tracking: no identity is
   * created or persisted and no events are queued or sent unless the
   * state is 'granted'.
   */
  var CONSENT_STORAGE_KEY = 'nylo_consent';

  var Consent = {
    read: function() {
      try {
        var stored = localStorage.getItem(CONSENT_STORAGE_KEY);
        if (stored === 'granted' || stored === 'denied' || stored === 'withdrawn') return stored;
      } catch (e) {}
      return 'unknown';
    },

    persist: function(value) {
      try { localStorage.setItem(CONSENT_STORAGE_KEY, value); } catch (e) {}
    },

    /**
     * Deletes every cookie, storage key and queued event the SDK creates.
     */
    purgeAllData: function() {
      try { document.cookie = 'nylo_wai=; path=/; max-age=0'; } catch (e) {}
      try {
        localStorage.removeItem('nylo_cross_domain_identity');
        localStorage.removeItem('nylo_identity');
      } catch (e) {}
      try {
        sessionStorage.removeItem('nylo_session_identity');
        sessionStorage.removeItem('nylo_identity');
      } catch (e) {}

      state.eventQueue = [];
      state.retryQueue = [];
      state.sessionId = null;
      state.waiTag = null;
      state.userId = null;
      state.crossDomainData.identitySynced = false;
      state.crossDomainData.tokenReceived = false;
      state.crossDomainData.referringDomain = null;
    }
  };

  function stopTracking() {
    if (state.batchTimer) {
      clearInterval(state.batchTimer);
      state.batchTimer = null;
    }
    state.listeners.forEach(function(handler, event) {
      if (event === 'scroll' || event === 'mouseover' || event === 'error' ||
          event === 'unhandledrejection' || event === 'beforeunload') {
        window.removeEventListener(event, handler);
      } else {
        document.removeEventListener(event, handler);
      }
    });
    state.listeners.clear();
    state.trackingStarted = false;
    state.trackingEpoch++; // invalidate any in-flight startup work

    // Withdrawal means stop NOW: kill requests already on the wire, cancel
    // scheduled retries, and drop the write grant so nothing can send.
    abortInflightRequests();
    clearPendingRetries();
    WriteGrant.invalidate();
  }

  function startTracking() {
    if (state.trackingStarted || state.consent !== 'granted') return;
    state.trackingStarted = true;

    var epoch = state.trackingEpoch;
    function cancelled() {
      return epoch !== state.trackingEpoch || state.consent !== 'granted';
    }

    var identityPromise;

    if (config.anonymousMode) {
      // Anonymous sessions still get cryptographically random IDs —
      // Math.random would make "anonymous" session IDs guessable.
      var anonId = Security.generateSecureId('anonymous');
      if (!anonId) {
        // Fail closed: without secure randomness there is no usable
        // session identifier. Do not track with a degraded or null one.
        Logger.error('Secure randomness unavailable - anonymous tracking disabled');
        state.trackingStarted = false;
        state.sessionId = null;
        return Promise.resolve();
      }
      state.sessionId = 'anon_' + anonId;
      state.waiTag = null;
      state.userId = null;
      Logger.info('Anonymous mode - no identity tracking');
      identityPromise = Promise.resolve();
    } else {
      identityPromise = CrossDomainIdentity.checkForCrossDomainToken(cancelled)
        .then(function(crossDomainSuccess) {
          if (cancelled()) return;
          if (!crossDomainSuccess) {
            return CrossDomainIdentity.getStoredIdentityData()
              .then(function(storedIdentity) {
                if (cancelled()) return;
                if (storedIdentity && storedIdentity.sessionId && storedIdentity.waiTag) {
                  state.sessionId = storedIdentity.sessionId;
                  state.waiTag = storedIdentity.waiTag;
                  state.userId = storedIdentity.userId;
                } else {
                  return CrossDomainIdentity.generateNewIdentity(cancelled);
                }
              });
          }
        });
    }

    return identityPromise
      .then(function() {
        if (cancelled()) return Promise.reject({ nyloCancelled: true });
        return parseEncryptedConfig(encryptedConfig, customerId);
      })
      .then(function() {
        if (cancelled()) return Promise.reject({ nyloCancelled: true });
        Tracking.pageView({
          initializationType: config.anonymousMode ? 'anonymous_session'
            : (state.crossDomainData.identitySynced ? 'cross_domain_arrival' : 'new_session'),
          waiTag: state.waiTag
        });

        setupEventListeners();
        setupPageLifecycle();

        state.batchTimer = setInterval(sendBatch, config.batchInterval);

        var duration = Performance.measure('init', 'init-start');
        state.performanceMetrics.timings.sdkInitDurationMs = duration || 0;
        Logger.info('Tracking started (' + (duration || 0).toFixed(2) + 'ms)');

        window.dispatchEvent(new CustomEvent('nyloInitialized', {
          detail: {
            version: config.version,
            waiTag: state.waiTag,
            crossDomainEnabled: !config.anonymousMode
          }
        }));
      })
      .catch(function(error) {
        if (error && error.nyloCancelled) {
          Logger.info('Tracking startup cancelled - consent revoked during initialization');
          // Only purge when consent is still not granted; a newer granted
          // epoch's data must never be erased by a stale cancelled startup.
          if (state.consent !== 'granted') Consent.purgeAllData();
          return;
        }
        if (error && error.nyloAborted) {
          // Deliberate fail-closed abort (e.g. secure randomness missing):
          // no identity, no listeners, no batch timer.
          state.trackingStarted = false;
          Logger.error('Tracking startup aborted: ' + error.nyloAborted);
          return;
        }
        Logger.error('Tracking startup failed:', error);
      });
  }

  function buildApi() {
    return {
      track: Tracking.customEvent,
      trackConversion: Tracking.conversion,
      identify: function(userId) {
        if (state.consent !== 'granted' || config.anonymousMode) {
          Logger.info('identify() ignored - consent not granted or anonymous mode');
          return;
        }
        state.userId = Security.sanitize(userId);
        CrossDomainIdentity.getStoredIdentityData()
          .then(function(identityData) {
            if (identityData) {
              identityData.userId = state.userId;
              return Security.generateIntegrityHMAC(
                identityData.sessionId, identityData.domain || '', identityData.waiTag
              ).then(function(hmac) {
                identityData.integrity = hmac;
                CrossDomainIdentity.storeIdentityData(identityData);
              });
            }
          })
          .catch(function() {});
      },
      getSession: function() {
        return {
          sessionId: state.sessionId,
          waiTag: state.waiTag,
          userId: state.userId,
          customerId: customerId,
          queueSize: state.eventQueue.length,
          crossDomainSynced: state.crossDomainData.identitySynced
        };
      },
      getCrossDomainIdentity: function() {
        return {
          waiTag: state.waiTag,
          identitySynced: state.crossDomainData.identitySynced,
          referringDomain: state.crossDomainData.referringDomain
        };
      },
      setConsent: function(consent) {
        if (consent && consent.analytics === false) {
          var wasGranted = state.consent === 'granted';
          state.consent = wasGranted ? 'withdrawn' : 'denied';
          Consent.persist(state.consent);
          stopTracking();
          Consent.purgeAllData();
          Logger.info(wasGranted
            ? 'Consent withdrawn - all identity data and queued events deleted'
            : 'Consent denied - tracking remains disabled');
        } else if (consent && consent.analytics === true) {
          state.consent = 'granted';
          Consent.persist('granted');
          startTracking();
          Logger.info('Consent granted - tracking enabled');
        }
      },
      getConsent: function() {
        return { analytics: state.consent === 'granted', state: state.consent };
      },
      flush: sendBatch,
      getMetrics: Performance.getMetrics,
      getTimingMetrics: Performance.getTimingMetrics,
      getFeatures: function() { return Object.assign({}, TrackingFeatures); },
      getEarlyCleanupScript: EarlyCleanup.getScript,
      version: config.version,
      destroy: cleanup
    };
  }

  function initialize() {
    if (state.initialized) return;

    Performance.mark('init-start');
    Logger.info('Initializing Nylo v' + config.version + ' for customer ' + customerId);

    if (encryptedSecurity) {
      var isAuthorized = validateDomainAuthorization(encryptedSecurity);
      if (!isAuthorized) {
        Logger.error('Domain not authorized - tracking blocked');
        return;
      }
    }

    if (script && script.getAttribute('data-anonymous') === 'true') {
      config.anonymousMode = true;
    }
    if (script && script.getAttribute('data-allow-query-params') === 'true') {
      config.allowQueryParamTokens = true;
    }

    state.consent = Consent.read();
    window.Nylo = buildApi();
    state.initialized = true;

    if (state.consent === 'granted') {
      startTracking();
    } else {
      Logger.info('Consent state is "' + state.consent + '" - tracking disabled until Nylo.setConsent({ analytics: true }) is called');
    }
  }

  var EarlyCleanup = {
    getScript: function() {
      return '<scr' + 'ipt>' +
        '(function(){' +
          'try{' +
            'var s=performance.now();' +
            'var h=window.location.hash;' +
            'if(h&&(h.indexOf("nylo_token=")>-1||h.indexOf("wai_token=")>-1)){' +
              'var p=new URLSearchParams(h.substring(1));' +
              'var t=p.get("nylo_token")||p.get("wai_token");' +
              'if(t){' +
                'window.__nylo_early_token=t;' +
                'window.__nylo_early_token_timing={start:s,navigationStart:performance.timeOrigin||performance.timing.navigationStart,detected:performance.now()};' +
                'p.delete("nylo_token");p.delete("wai_token");' +
                'var n=p.toString();' +
                'history.replaceState(null,"",window.location.pathname+window.location.search+(n?"#"+n:""));' +
                'window.__nylo_early_token_timing.cleaned=performance.now();' +
                'window.__nylo_early_token_timing.duration=window.__nylo_early_token_timing.cleaned-s;' +
              '}' +
            '}' +
          '}catch(e){}' +
        '})();' +
      '</scr' + 'ipt>';
    }
  };

  function cleanup() {
    if (state.batchTimer) {
      clearInterval(state.batchTimer);
      state.batchTimer = null;
    }

    state.listeners.forEach(function(handler, event) {
      if (event === 'scroll' || event === 'mouseover' || event === 'error' ||
          event === 'unhandledrejection' || event === 'beforeunload') {
        window.removeEventListener(event, handler);
      } else {
        document.removeEventListener(event, handler);
      }
    });
    state.listeners.clear();

    if (state.eventQueue.length > 0) sendBatch();

    state.initialized = false;
    Logger.info('Cleanup complete');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }
})();
