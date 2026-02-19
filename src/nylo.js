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
    anonymousMode: false
  };

  var state = {
    initialized: false,
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
      crossDomainSyncs: 0
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
    trackCrossDomain: true,
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
      return /^wai_[0-9a-zA-Z]{10,}_[a-zA-Z0-9]{8,}$/.test(waiTag);
    },

    generateCSRFToken: function() {
      return Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
    },

    generateSecureId: function(domain) {
      var timestamp = Date.now();
      var randomBytes = new Uint8Array(16);

      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(randomBytes);
      } else {
        for (var i = 0; i < randomBytes.length; i++) {
          randomBytes[i] = Math.floor(Math.random() * 256);
        }
      }

      var randomHex = Array.from(randomBytes, function(byte) {
        return byte.toString(16).padStart(2, '0');
      }).join('');

      var domainHash = this.hashString(domain || 'default').substring(0, 8);
      return timestamp.toString(36) + '-' + randomHex + '-' + domainHash;
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
      var timestamp = Date.now();
      var randomBytes = new Uint8Array(8);

      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(randomBytes);
      } else {
        for (var i = 0; i < randomBytes.length; i++) {
          randomBytes[i] = Math.floor(Math.random() * 256);
        }
      }

      var randomId = Array.from(randomBytes, function(byte) {
        return byte.toString(36);
      }).join('').substring(0, 11);

      var domainHash = this.hashString(domain || 'default').substring(0, 8);
      return 'wai_' + timestamp.toString(36) + '_' + randomId + domainHash;
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
        retryQueueSize: state.retryQueue.length
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
    checkForCrossDomainToken: function() {
      var crossDomainToken = null;
      var hash = window.location.hash;
      if (hash) {
        var hashParams = new URLSearchParams(hash.substring(1));
        crossDomainToken = hashParams.get('nylo_token') || hashParams.get('wai_token');
      }
      if (!crossDomainToken) {
        var urlParams = new URLSearchParams(window.location.search);
        crossDomainToken = urlParams.get('nylo_token') || urlParams.get('wai_token');
      }

      if (crossDomainToken) {
        Logger.info('Cross-domain token detected');
        state.crossDomainData.tokenReceived = true;
        try {
          state.crossDomainData.referringDomain = document.referrer ? new URL(document.referrer).hostname : null;
        } catch (e) {
          state.crossDomainData.referringDomain = null;
        }
        return this.verifyAndProcessToken(crossDomainToken);
      }

      return Promise.resolve(false);
    },

    verifyAndProcessToken: function(token) {
      var self = this;
      var domain = window.location.hostname;

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
        if (result.success && result.identity) {
          state.sessionId = result.identity.sessionId;
          state.waiTag = result.identity.waiTag;
          state.userId = result.identity.userId;
          state.crossDomainData.identitySynced = true;
          state.performanceMetrics.crossDomainSyncs++;

          self.storeIdentityData({
            sessionId: state.sessionId,
            waiTag: state.waiTag,
            userId: state.userId,
            domain: domain,
            syncedAt: new Date().toISOString()
          });

          self.trackCrossDomainEvent('cross_domain_arrival', {
            referringDomain: state.crossDomainData.referringDomain,
            tokenVerified: true,
            identityPreserved: true
          });

          Logger.info('Cross-domain identity synchronized');
          return true;
        }
        return false;
      })
      .catch(function(error) {
        Logger.error('Cross-domain token verification failed:', error);
        return false;
      });
    },

    generateNewIdentity: function() {
      var domain = window.location.hostname;

      state.sessionId = Security.generateSecureId(domain);
      state.waiTag = Security.generateWaiTag(domain);

      var identityData = {
        sessionId: state.sessionId,
        waiTag: state.waiTag,
        userId: state.userId,
        domain: domain,
        createdAt: new Date().toISOString(),
        integrity: Security.generateIntegrityHash(state.sessionId, domain, state.waiTag)
      };

      this.storeIdentityData(identityData);
      this.registerIdentityWithServer(identityData);

      Logger.info('New identity generated:', state.waiTag);
    },

    storeIdentityData: function(identityData) {
      try {
        var cookieData = btoa(JSON.stringify(identityData));
        document.cookie = 'nylo_wai=' + cookieData + '; path=/; SameSite=Lax; max-age=86400';
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

    getStoredIdentityData: function() {
      try {
        var cookies = document.cookie.split(';');
        var waiCookie = cookies.find(function(c) { return c.trim().startsWith('nylo_wai='); });
        if (waiCookie) {
          var cookieData = waiCookie.split('=')[1];
          return JSON.parse(atob(cookieData));
        }
      } catch (e) {}

      try {
        var encryptedData = localStorage.getItem('nylo_cross_domain_identity');
        if (encryptedData) return this.decryptIdentityData(encryptedData);
      } catch (e) {}

      try {
        var sessionData = sessionStorage.getItem('nylo_session_identity');
        if (sessionData) return JSON.parse(sessionData);
      } catch (e) {}

      return null;
    },

    registerIdentityWithServer: function(identityData) {
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
  function parseEncryptedConfig(encConfig, custId) {
    if (!encConfig) {
      TrackingFeatures.trackPageViews = true;
      TrackingFeatures.trackClicks = true;
      TrackingFeatures.trackCrossDomain = true;
      return Promise.resolve(TrackingFeatures);
    }

    return deriveKey(custId)
      .then(function(key) { return decryptConfig(encConfig, key); })
      .then(function(decryptedData) {
        var cfg = JSON.parse(decryptedData);

        Object.keys(TrackingFeatures).forEach(function(feature) {
          TrackingFeatures[feature] = false;
        });
        TrackingFeatures.trackCrossDomain = true;

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
        TrackingFeatures.trackPageViews = true;
        TrackingFeatures.trackClicks = true;
        TrackingFeatures.trackCrossDomain = true;
        return TrackingFeatures;
      });
  }

  function deriveKey(custId) {
    var encoder = new TextEncoder();
    var data = encoder.encode(custId + 'nylo_key_salt');

    if (window.crypto && window.crypto.subtle) {
      return window.crypto.subtle.digest('SHA-256', data)
        .then(function(hashBuffer) { return new Uint8Array(hashBuffer); });
    }

    return Promise.resolve(new Uint8Array(32).fill(0));
  }

  function decryptConfig(encConfig, key) {
    if (window.crypto && window.crypto.subtle) {
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
        // Fall through to base64 fallback
      }
    }

    try {
      return Promise.resolve(atob(encConfig));
    } catch (error) {
      return Promise.reject(new Error('All decryption methods failed'));
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
            return currentDomain.endsWith(baseDomain);
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

  function initialize() {
    if (state.initialized) return;

    Performance.mark('init-start');
    Logger.info('Initializing Nylo v' + config.version + ' for customer ' + customerId);

    var initPromise = Promise.resolve();

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

    if (config.anonymousMode) {
      state.sessionId = 'anon_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2, 10);
      state.waiTag = null;
      state.userId = null;
      Logger.info('Anonymous mode - no identity tracking');

      parseEncryptedConfig(encryptedConfig, customerId)
        .then(function() {
          Tracking.pageView({
            initializationType: 'anonymous_session',
            waiTag: null
          });

          setupEventListeners();
          setupPageLifecycle();

          state.batchTimer = setInterval(sendBatch, config.batchInterval);

          window.Nylo = {
            track: Tracking.customEvent,
            trackConversion: Tracking.conversion,
            identify: function() {
              Logger.info('identify() is a no-op in anonymous mode');
            },
            getSession: function() {
              return {
                sessionId: state.sessionId,
                waiTag: null,
                userId: null,
                customerId: customerId,
                queueSize: state.eventQueue.length,
                crossDomainSynced: false
              };
            },
            getCrossDomainIdentity: function() {
              return {
                waiTag: null,
                identitySynced: false,
                referringDomain: null
              };
            },
            setConsent: function(consent) {
              if (consent && consent.analytics === false) {
                state.waiTag = null;
                state.userId = null;
                state.crossDomainData.identitySynced = false;
                config.anonymousMode = true;
                try { localStorage.removeItem('nylo_identity'); } catch(e) {}
                try { sessionStorage.removeItem('nylo_identity'); } catch(e) {}
                Logger.info('Consent denied - switched to anonymous mode');
              } else if (consent && consent.analytics === true) {
                config.anonymousMode = false;
                var storedIdentity = CrossDomainIdentity.getStoredIdentityData();
                if (storedIdentity && storedIdentity.sessionId && storedIdentity.waiTag) {
                  state.sessionId = storedIdentity.sessionId;
                  state.waiTag = storedIdentity.waiTag;
                  state.userId = storedIdentity.userId;
                } else {
                  CrossDomainIdentity.generateNewIdentity();
                }
                CrossDomainIdentity.checkForCrossDomainToken();
                Logger.info('Consent granted - identity tracking enabled');
              }
            },
            getConsent: function() {
              return { analytics: !config.anonymousMode };
            },
            flush: sendBatch,
            getMetrics: Performance.getMetrics,
            getFeatures: function() { return Object.assign({}, TrackingFeatures); },
            version: config.version,
            destroy: cleanup
          };

          state.initialized = true;

          var duration = Performance.measure('init', 'init-start');
          Logger.info('Initialization complete (' + (duration || 0).toFixed(2) + 'ms)');

          window.dispatchEvent(new CustomEvent('nyloInitialized', {
            detail: {
              version: config.version,
              waiTag: state.waiTag,
              crossDomainEnabled: false
            }
          }));
        })
        .catch(function(error) {
          Logger.error('Initialization failed:', error);
          Tracking.error(error, { context: 'initialization' });
        });
      return;
    }

    CrossDomainIdentity.checkForCrossDomainToken()
      .then(function(crossDomainSuccess) {
        if (!crossDomainSuccess) {
          var storedIdentity = CrossDomainIdentity.getStoredIdentityData();
          if (storedIdentity && storedIdentity.sessionId && storedIdentity.waiTag) {
            state.sessionId = storedIdentity.sessionId;
            state.waiTag = storedIdentity.waiTag;
            state.userId = storedIdentity.userId;
          } else {
            CrossDomainIdentity.generateNewIdentity();
          }
        }

        return parseEncryptedConfig(encryptedConfig, customerId);
      })
      .then(function() {
        Tracking.pageView({
          initializationType: state.crossDomainData.identitySynced ? 'cross_domain_arrival' : 'new_session',
          waiTag: state.waiTag
        });

        setupEventListeners();
        setupPageLifecycle();

        state.batchTimer = setInterval(sendBatch, config.batchInterval);

        window.Nylo = {
          track: Tracking.customEvent,
          trackConversion: Tracking.conversion,
          identify: function(userId) {
            state.userId = Security.sanitize(userId);
            var identityData = CrossDomainIdentity.getStoredIdentityData();
            if (identityData) {
              identityData.userId = state.userId;
              CrossDomainIdentity.storeIdentityData(identityData);
            }
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
              state.waiTag = null;
              state.userId = null;
              state.crossDomainData.identitySynced = false;
              config.anonymousMode = true;
              try { localStorage.removeItem('nylo_identity'); } catch(e) {}
              try { sessionStorage.removeItem('nylo_identity'); } catch(e) {}
              Logger.info('Consent denied - switched to anonymous mode');
            } else if (consent && consent.analytics === true) {
              config.anonymousMode = false;
              CrossDomainIdentity.generateNewIdentity();
              Logger.info('Consent granted - identity tracking enabled');
            }
          },
          getConsent: function() {
            return { analytics: !config.anonymousMode };
          },
          flush: sendBatch,
          getMetrics: Performance.getMetrics,
          getFeatures: function() { return Object.assign({}, TrackingFeatures); },
          version: config.version,
          destroy: cleanup
        };

        state.initialized = true;

        var duration = Performance.measure('init', 'init-start');
        Logger.info('Initialization complete (' + (duration || 0).toFixed(2) + 'ms)');

        window.dispatchEvent(new CustomEvent('nyloInitialized', {
          detail: {
            version: config.version,
            waiTag: state.waiTag,
            crossDomainEnabled: true
          }
        }));
      })
      .catch(function(error) {
        Logger.error('Initialization failed:', error);
        Tracking.error(error, { context: 'initialization' });
      });
  }

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
