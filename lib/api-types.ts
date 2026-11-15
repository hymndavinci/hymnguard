// Response shapes returned by /api/check/*, shared by the client UI.

import type { DomainCheckResult } from "./domain-check";
import type { EmailAuthResult } from "./email-auth";
import type {
  HudsonRockResult,
  LeakCheckResult,
  OsintCatResult,
} from "./email-breach";
import type { EnumChunkResult, EnumSiteResult } from "./email-enumeration";
import type { GitHubExposureResult } from "./github-exposure";
import type { HibpBreachMeta, PwnedRangeEntry } from "./hibp";
import type { IpCheckResult } from "./ip-check";
import type { PhoneCheckResult } from "./phone-check";
import type { UsernameCheckResult } from "./username-check";

export type {
  DomainCheckResult,
  EmailAuthResult,
  EnumChunkResult,
  EnumSiteResult,
  GitHubExposureResult,
  HudsonRockResult,
  IpCheckResult,
  LeakCheckResult,
  OsintCatResult,
  PhoneCheckResult,
  UsernameCheckResult,
};

export interface PasswordCheckResponse {
  prefix: string;
  entries: PwnedRangeEntry[];
}

/** One chunk of a username check, plus the chunk plan for aggregation. */
export interface UsernameChunkResponse extends UsernameCheckResult {
  chunk: number;
  chunkSize: number;
  total: number;
  chunks: number;
}

export interface UsernamePlanResponse {
  total: number;
  chunkSize: number;
  chunks: number;
}

export interface EmailCheckResponse {
  email: string;
  domain: string;
  checkedAt: string;
  mx: { exchange: string; priority: number }[];
  mxOk: boolean;
  mxError?: string;
  disposable: boolean;
  hibp: {
    available: boolean;
    rateLimited?: boolean;
    breaches?: HibpBreachMeta[];
    /** Present when the lookup itself failed (e.g. a rejected API key). */
    error?: string;
  };
  /** SPF / DMARC / DKIM grading for the email's domain (DNS-only). */
  auth: EmailAuthResult;
  /** LeakCheck public API (free, no key). */
  leakcheck: LeakCheckResult;
  /** OsintCat breach lookup (keyed). */
  osintcat: { available: boolean; result?: OsintCatResult };
  /** Hudson Rock infostealer exposure (free, no key). */
  hudsonrock: HudsonRockResult;
  /** Public GitHub commits authored with this email (keyed). */
  github: { available: boolean; result?: GitHubExposureResult };
  /** Whether account enumeration is configured (Resend + VERIFY_SECRET). */
  enumeration: { available: boolean };
}

/** One chunk of an enumeration check, plus the chunk plan. */
export interface EnumPlanResponse {
  total: number;
  chunkSize: number;
  chunks: number;
}

export interface VerifyRequestResponse {
  /** Present when the code was sent. Binds email + code + expiry (HMAC). */
  token?: string;
  expiresInSec?: number;
}

export interface VerifyResponse {
  verified: boolean;
  /** HMAC-signed token authorizing enumeration for this email. */
  verificationToken?: string;
  expiresInSec?: number;
}
