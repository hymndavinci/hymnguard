// Phone checks: format / country / validity (libphonenumber-js, free,
// offline), Indonesian operator from the offline prefix table, carrier +
// risk via IPQS (keyed), and community spam reports from GetContact and
// Should I Answer (free, no key).
//
// There is no free, legitimate source for phone-number breach lookups,
// and the UI says so. IPQS's `leaked` flag (keyed) is the closest thing:
// a boolean only, never breach contents.

import { parsePhoneNumber } from "libphonenumber-js";
import { lookupIdOperator, type IdOperator } from "./id-prefixes";
import { fetchIpqsPhone, type IpqsPhoneResult } from "./phone-carrier";
import {
  fetchGetContact,
  fetchShouldIAnswer,
  type GetContactResult,
  type ShouldIAnswerResult,
} from "./phone-spam";

export interface PhoneCheckResult {
  input: string;
  checkedAt: string;
  valid: boolean;
  possible: boolean;
  country: string | undefined;
  countryCallingCode: string | undefined;
  type: string | undefined;
  e164: string | undefined;
  international: string | undefined;
  national: string | undefined;
  /** Indonesian operator from the offline prefix table (ID numbers only). */
  idOperator: IdOperator | null;
  /** IPQS carrier + risk lookup (keyed). */
  ipqs: { available: boolean; result?: IpqsPhoneResult };
  /** Community spam reports (best-effort, public data). */
  spam: {
    getcontact: GetContactResult;
    shouldianswer: ShouldIAnswerResult;
  };
}

const SKIPPED =
  "Skipped — the number is not valid, so reputation checks were not run.";

function skippedSpam(e164: string): PhoneCheckResult["spam"] {
  return {
    getcontact: {
      ok: false,
      inDatabase: false,
      error: SKIPPED,
      url: `https://getcontact.com/number-lookup/id/p/${e164.replace(/^\+/, "")}`,
    },
    shouldianswer: { ok: false, covered: false, error: SKIPPED },
  };
}

export async function checkPhone(
  input: string,
  opts: { ipqsKey?: string } = {},
): Promise<PhoneCheckResult> {
  const trimmed = input.trim();
  const checkedAt = new Date().toISOString();
  const base = {
    input: trimmed,
    checkedAt,
    valid: false,
    possible: false,
    country: undefined as string | undefined,
    countryCallingCode: undefined as string | undefined,
    type: undefined as string | undefined,
    e164: undefined as string | undefined,
    international: undefined as string | undefined,
    national: undefined as string | undefined,
    idOperator: null as IdOperator | null,
  };

  let parsed;
  try {
    parsed = parsePhoneNumber(trimmed);
  } catch {
    return {
      ...base,
      ipqs: { available: false },
      spam: skippedSpam(trimmed),
    };
  }

  const e164 = parsed.number;
  const result: PhoneCheckResult = {
    ...base,
    valid: parsed.isValid(),
    possible: parsed.isPossible(),
    country: parsed.country,
    countryCallingCode: parsed.countryCallingCode,
    type: parsed.getType(),
    e164,
    international: parsed.formatInternational(),
    national: parsed.formatNational(),
    idOperator:
      parsed.country === "ID" ? lookupIdOperator(e164) : null,
    ipqs: { available: false },
    spam: skippedSpam(e164),
  };

  // Reputation checks only run for valid numbers — they cost API credits
  // (IPQS) and are meaningless for malformed numbers.
  if (!result.valid) return result;

  const [ipqs, getcontact, shouldianswer] = await Promise.all([
    (async (): Promise<{ available: boolean; result?: IpqsPhoneResult }> => {
      if (!opts.ipqsKey) return { available: false };
      return {
        available: true,
        result: await fetchIpqsPhone(e164, opts.ipqsKey, parsed.country),
      };
    })(),
    fetchGetContact(e164, parsed.country),
    fetchShouldIAnswer(e164, parsed.countryCallingCode),
  ]);

  result.ipqs = ipqs;
  result.spam = { getcontact, shouldianswer };
  return result;
}
