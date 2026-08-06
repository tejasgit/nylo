/**
 * Nylo Event Envelope — versioned client/server batching contract.
 *
 * This module is the single source of truth for the shape of event batches
 * exchanged between the Nylo browser SDK and any Nylo ingestion server
 * (the TypeScript server and all example/demo servers).
 *
 * Envelope (schemaVersion 1):
 * {
 *   schemaVersion: 1,
 *   batchId: "<hex>",              // client-generated batch identifier
 *   sentAt: "<ISO 8601>",          // client send time for the batch
 *   common: {                      // fields shared by every event in the batch
 *     sessionId, userId, waiTag, domain, customerId
 *   },
 *   events: [                      // per-event fields (common fields stripped)
 *     {
 *       eventId: "<32-64 hex>",    // client-generated cryptographic id (dedup key)
 *       eventType: "page_view",
 *       timestamp: "<ISO 8601>",   // client event time
 *       ...otherEventFields
 *     }
 *   ]
 * }
 *
 * Copyright (c) 2024-2026 Nylo Contributors
 * Licensed under MIT License (see LICENSE)
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.NyloEventEnvelope = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var SCHEMA_VERSION = 1;

  var LIMITS = {
    MAX_EVENTS_PER_BATCH: 100,
    MAX_EVENT_BYTES: 32 * 1024,      // 32 KB per serialized event
    MAX_BATCH_BYTES: 1024 * 1024     // 1 MB per serialized request body
  };

  var COMMON_FIELDS = ['sessionId', 'userId', 'waiTag', 'domain', 'customerId'];
  var EVENT_ID_PATTERN = /^[0-9a-f]{32,64}$/;

  function byteLength(value) {
    var str = typeof value === 'string' ? value : JSON.stringify(value);
    if (typeof Buffer !== 'undefined' && Buffer.byteLength) {
      return Buffer.byteLength(str, 'utf8');
    }
    // Browser fallback
    return new Blob ? new Blob([str]).size : str.length;
  }

  /**
   * Build a v1 envelope from an array of full event objects.
   * Common fields are hoisted from the first event; per-event copies are
   * stripped only when they match the common value (lossless compression).
   */
  function buildEnvelope(events, options) {
    options = options || {};
    var first = events[0] || {};
    var common = {};
    COMMON_FIELDS.forEach(function (field) {
      var value = field === 'customerId' && options.customerId !== undefined
        ? options.customerId
        : first[field];
      if (value !== undefined && value !== null) common[field] = value;
    });

    var compressed = events.map(function (event) {
      var copy = {};
      Object.keys(event).forEach(function (key) {
        if (COMMON_FIELDS.indexOf(key) !== -1 && event[key] === common[key]) return;
        copy[key] = event[key];
      });
      return copy;
    });

    return {
      schemaVersion: SCHEMA_VERSION,
      batchId: options.batchId || null,
      sentAt: options.sentAt || new Date().toISOString(),
      common: common,
      events: compressed
    };
  }

  /**
   * Parse and validate a request body into full (expanded) events.
   *
   * Returns:
   *   { ok: true, schemaVersion, batchId, sentAt, common, events: [fullEvent...] }
   * or
   *   { ok: false, status: 400, error: "<machine code>", message: "<human message>" }
   *
   * Accepted inputs:
   *   - v1 envelope ({ schemaVersion: 1, common, events })
   *   - legacy plain array of events, or { events: [...] }, or a single event
   *     object (no schemaVersion). Legacy input is expanded as-is.
   * Rejected (400):
   *   - unknown schemaVersion
   *   - schemaVersion present but events missing/not an array/empty
   *   - non-object events, missing/invalid eventId in v1
   *   - batches or events over size limits
   */
  function parseEnvelope(body) {
    function fail(error, message) {
      return { ok: false, status: 400, error: error, message: message };
    }

    if (body === null || typeof body !== 'object') {
      return fail('INVALID_BODY', 'Request body must be a JSON object or array');
    }

    var serializedSize = byteLength(body);
    if (serializedSize > LIMITS.MAX_BATCH_BYTES) {
      return fail('BATCH_TOO_LARGE', 'Batch exceeds ' + LIMITS.MAX_BATCH_BYTES + ' bytes');
    }

    var isVersioned = !Array.isArray(body) && body.schemaVersion !== undefined;

    if (isVersioned && body.schemaVersion !== SCHEMA_VERSION) {
      return fail('UNSUPPORTED_SCHEMA_VERSION',
        'Unsupported schemaVersion: ' + JSON.stringify(body.schemaVersion) +
        ' (supported: ' + SCHEMA_VERSION + ')');
    }

    var rawEvents;
    var common = {};

    if (isVersioned) {
      if (!Array.isArray(body.events)) {
        return fail('INVALID_EVENTS', 'Envelope "events" must be an array');
      }
      if (body.common !== undefined) {
        if (body.common === null || typeof body.common !== 'object' || Array.isArray(body.common)) {
          return fail('INVALID_COMMON', 'Envelope "common" must be an object');
        }
        common = body.common;
      }
      rawEvents = body.events;
    } else if (Array.isArray(body)) {
      rawEvents = body;
    } else if (body.events !== undefined) {
      // Legacy shapes: { events: [...] } or the old broken { events: { common, events } }
      if (Array.isArray(body.events)) {
        if (body.common && typeof body.common === 'object' && !Array.isArray(body.common)) {
          common = body.common;
        }
        rawEvents = body.events;
      } else if (body.events && typeof body.events === 'object' &&
                 Array.isArray(body.events.events)) {
        common = (body.events.common && typeof body.events.common === 'object')
          ? body.events.common : {};
        rawEvents = body.events.events;
      } else {
        return fail('INVALID_EVENTS', '"events" must be an array of event objects');
      }
    } else {
      // Legacy single-event body
      rawEvents = [body];
    }

    if (rawEvents.length === 0) {
      return fail('EMPTY_BATCH', 'No events provided');
    }
    if (rawEvents.length > LIMITS.MAX_EVENTS_PER_BATCH) {
      return fail('TOO_MANY_EVENTS',
        'Batch has ' + rawEvents.length + ' events (max ' + LIMITS.MAX_EVENTS_PER_BATCH + ')');
    }

    var expanded = [];
    for (var i = 0; i < rawEvents.length; i++) {
      var raw = rawEvents[i];
      if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
        return fail('INVALID_EVENT', 'Event at index ' + i + ' is not an object');
      }
      if (byteLength(raw) > LIMITS.MAX_EVENT_BYTES) {
        return fail('EVENT_TOO_LARGE',
          'Event at index ' + i + ' exceeds ' + LIMITS.MAX_EVENT_BYTES + ' bytes');
      }
      if (isVersioned) {
        if (typeof raw.eventId !== 'string' || !EVENT_ID_PATTERN.test(raw.eventId)) {
          return fail('INVALID_EVENT_ID',
            'Event at index ' + i + ' is missing a valid eventId (32-64 hex chars)');
        }
      }
      var full = {};
      Object.keys(common).forEach(function (key) { full[key] = common[key]; });
      Object.keys(raw).forEach(function (key) { full[key] = raw[key]; });
      expanded.push(full);
    }

    // Duplicate eventIds inside the same batch are rejected as malformed.
    if (isVersioned) {
      var seen = {};
      for (var j = 0; j < expanded.length; j++) {
        var id = expanded[j].eventId;
        if (seen[id]) {
          return fail('DUPLICATE_EVENT_ID', 'Duplicate eventId within batch: ' + id);
        }
        seen[id] = true;
      }
    }

    return {
      ok: true,
      schemaVersion: isVersioned ? SCHEMA_VERSION : 0,
      batchId: (!Array.isArray(body) && typeof body.batchId === 'string') ? body.batchId : null,
      sentAt: (!Array.isArray(body) && typeof body.sentAt === 'string') ? body.sentAt
        : (!Array.isArray(body) && typeof body.timestamp === 'string') ? body.timestamp : null,
      common: common,
      events: expanded
    };
  }

  return {
    SCHEMA_VERSION: SCHEMA_VERSION,
    LIMITS: LIMITS,
    COMMON_FIELDS: COMMON_FIELDS,
    EVENT_ID_PATTERN: EVENT_ID_PATTERN,
    buildEnvelope: buildEnvelope,
    parseEnvelope: parseEnvelope
  };
});
