/**
 * Nylo Analytics SDK v1.0.0
 * Privacy-first cross-domain analytics tracking
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 *
 * COMMERCIAL NOTICE: Cross-domain identity features (WTX-1 protocol,
 * WaiTag system, encrypted configuration) require a commercial license
 * for production use. See COMMERCIAL-LICENSE for details.
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

  var Compression = {
    compress: function(data) {
      if (!config.compressionEnabled) return data;
      try {
        var compressed = data.map(function(event) {
          var rest = Object.assign({}, event);
          delete rest.sessionId;
          delete rest.userId;
          delete rest.waiTag;
          delete rest.domain;
          delete rest.customerId;
          return rest;
        });
        return {
          common: {
            sessionId: data[0]?.sessionId,
            userId: data[0]?.userId,
            waiTag: data[0]?.waiTag,
            domain: data[0]?.domain,
            customerId: customerId
          },
          events: compressed
        };
      } catch (e) {
        Logger.error('Compression failed:', e);
        return data;
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

        return this.verifyAndProcessToken(crossDomainToken);
      }

      return Promise.resolve(false);
    },

    verifyAndProcessToken: function(token) {
      var self = this;
      var domain = window.location.hostname;
      var verificationStartTime = performance.now();
      state.performanceMetrics.timings.tokenVerificationStartMs = verificationStartTime;

      return fetch(getApiUrl() + '/api/tracking/verify-cross-domain-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          token: token,
          domain: domain,
          customerId: customerId,
          referrer: document.referrer
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
    },

    generateNewIdentity: function(isCancelled) {
      isCancelled = isCancelled || function() { return false; };
      var self = this;
      var domain = window.location.hostname;

      if (isCancelled()) return Promise.resolve();

      state.sessionId = Security.generateSecureId(domain);
      state.waiTag = Security.generateWaiTag(domain);

      if (!state.sessionId || !state.waiTag) {
        Logger.error('Failed to generate secure identity — crypto API unavailable');
        state.sessionId = state.sessionId || 'anon_' + Date.now().toString(36);
        state.waiTag = null;
        return Promise.resolve();
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
        var encryptedData = this.encryptIdentityData(identityData);
        localStorage.setItem('nylo_cross_domain_identity', encryptedData);
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
        var encryptedData = localStorage.getItem('nylo_cross_domain_identity');
        if (encryptedData) {
          var decrypted = this.decryptIdentityData(encryptedData);
          if (decrypted) candidates.push({ source: 'localStorage', data: decrypted });
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
      fetch(getApiUrl() + '/api/tracking/register-waitag', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          waiTag: identityData.waiTag,
          sessionId: identityData.sessionId,
          domain: identityData.domain,
          customerId: customerId,
          timestamp: identityData.createdAt,
          userAgent: navigator.userAgent
        })
      }).catch(function() {});
    },

    encryptIdentityData: function(data) {
      var jsonStr = JSON.stringify(data);
      var timestamp = Date.now().toString(36);
      var salt = customerId + timestamp;
      var encoded = btoa(jsonStr + salt);
      return encoded + '.' + timestamp;
    },

    decryptIdentityData: function(encryptedStr) {
      try {
        var parts = encryptedStr.split('.');
        if (parts.length !== 2) return null;
        var encoded = parts[0];
        var timestamp = parts[1];
        var salt = customerId + timestamp;
        var decoded = atob(encoded);
        if (!decoded.endsWith(salt)) return null;
        var jsonStr = decoded.substring(0, decoded.length - salt.length);
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
    var mainDomain = domain;
    var subdomain = null;

    var domainParts = domain.split('.');
    if (domainParts.length > 2) {
      subdomain = domainParts[0];
      mainDomain = domainParts.slice(1).join('.');
    }

    var event = {
      sessionId: state.sessionId,
      waiTag: state.waiTag,
      userId: state.userId,
      customerId: customerId,
      embedId: embedId,
      timestamp: new Date().toISOString(),
      eventType: eventType,
      domain: domain,
      mainDomain: mainDomain,
      subdomain: subdomain,
      url: window.location.href,
      path: window.location.pathname,
      title: document.title,
      referrer: document.referrer,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
      screenWidth: screen.width,
      screenHeight: screen.height,
      language: navigator.language,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      metadata: Security.sanitize(JSON.stringify(metadata)),
      crossDomainContext: state.crossDomainData.identitySynced ? {
        referringDomain: state.crossDomainData.referringDomain,
        identityPreserved: true,
        syncMethod: 'token_verification'
      } : null
    };

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
        errorMessage: error.message || String(error),
        errorStack: error.stack,
        errorContext: context || {}
      });
    }
  };

  var retryCount = 0;
  var isCircuitBreakerOpen = false;

  function sendBatch() {
    if (state.consent !== 'granted') return;
    if (state.eventQueue.length === 0) return;
    if (isCircuitBreakerOpen) return;

    Performance.mark('batch-start');
    var batch = state.eventQueue.splice(0, config.batchSize);
    var compressedBatch = Compression.compress(batch);

    var requestOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Customer-ID': customerId,
        'X-Session-ID': state.sessionId,
        'X-WaiTag': state.waiTag,
        'X-Batch-Size': batch.length.toString(),
        'X-SDK-Version': config.version
      },
      credentials: 'include',
      body: JSON.stringify({
        events: compressedBatch,
        batchId: Security.generateCSRFToken(),
        timestamp: new Date().toISOString()
      })
    };

    fetch(getApiUrl() + '/api/track', requestOptions)
      .then(function(response) {
        if (!response.ok) throw new Error('HTTP ' + response.status);
        return response.json();
      })
      .then(function() {
        retryCount = 0;
        isCircuitBreakerOpen = false;
        state.performanceMetrics.batchesSent++;
        state.performanceMetrics.lastBatchTime = Date.now();
        Performance.measure('batch-send', 'batch-start');
      })
      .catch(function() {
        state.performanceMetrics.errors++;

        if (retryCount < config.maxRetries) {
          state.retryQueue.push.apply(state.retryQueue, batch);
          var retryDelay = Math.pow(2, retryCount) * 1000;
          retryCount++;

          setTimeout(function() {
            var retryBatch = state.retryQueue.splice(0, config.batchSize);
            if (retryBatch.length > 0) {
              state.eventQueue.unshift.apply(state.eventQueue, retryBatch);
              sendBatch();
            }
          }, retryDelay);
        } else {
          isCircuitBreakerOpen = true;
          setTimeout(function() {
            isCircuitBreakerOpen = false;
            retryCount = 0;
          }, 30000);
        }
      });
  }

  function setupEventListeners() {
    var clickHandler = function(e) {
      if (!TrackingFeatures.trackClicks) return;
      var target = e.target.closest('a, button, [role="button"], input[type="submit"]');
      if (target) {
        Tracking.click(target, {
          clickX: e.clientX,
          clickY: e.clientY,
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
        formAction: e.target.action,
        formMethod: e.target.method,
        fieldCount: e.target.elements.length
      });
    };
    document.addEventListener('submit', formHandler);
    state.listeners.set('submit', formHandler);

    var errorHandler = function(e) {
      Tracking.error(e.error || new Error(e.message), {
        filename: e.filename,
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
      state.sessionId = 'anon_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 10);
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
