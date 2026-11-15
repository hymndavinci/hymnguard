// Response shapes returned by /api/check/*, shared by the client UI.

import type { DomainCheckResult } from "./domain-check";
import type { HibpBreachMeta, PwnedRangeEntry } from "./hibp";
import type { PhoneCheckResult } from "./phone-check";
import type { UsernameCheckResult } from "./username-check";

export type { DomainCheckResult, PhoneCheckResult, UsernameCheckResult };

export interface PasswordCheckResponse {
  prefix: string;
  entries: PwnedRangeEntry[];
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
  };
}
