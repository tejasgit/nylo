/** Type declarations for the shared Nylo event envelope contract. */

export const SCHEMA_VERSION: 1;

export const LIMITS: {
  MAX_EVENTS_PER_BATCH: number;
  MAX_EVENT_BYTES: number;
  MAX_BATCH_BYTES: number;
};

export const COMMON_FIELDS: string[];
export const EVENT_ID_PATTERN: RegExp;

export interface EnvelopeV1 {
  schemaVersion: 1;
  batchId: string | null;
  sentAt: string;
  common: Record<string, any>;
  events: Record<string, any>[];
}

export interface ParseSuccess {
  ok: true;
  schemaVersion: number;
  batchId: string | null;
  sentAt: string | null;
  common: Record<string, any>;
  events: Record<string, any>[];
}

export interface ParseFailure {
  ok: false;
  status: 400;
  error: string;
  message: string;
}

export function buildEnvelope(
  events: Record<string, any>[],
  options?: { batchId?: string; sentAt?: string; customerId?: string }
): EnvelopeV1;

export function parseEnvelope(body: unknown): ParseSuccess | ParseFailure;
