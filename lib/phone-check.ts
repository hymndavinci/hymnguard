// Phone parsing with libphonenumber-js (free, offline metadata).
// This is format / country / validity information only. There is no free,
// legitimate source for phone-number breach lookups, and the UI says so.

import { parsePhoneNumber } from "libphonenumber-js";

export interface PhoneCheckResult {
  input: string;
  valid: boolean;
  possible: boolean;
  country: string | undefined;
  countryCallingCode: string | undefined;
  type: string | undefined;
  e164: string | undefined;
  international: string | undefined;
  national: string | undefined;
}

export function checkPhone(input: string): PhoneCheckResult {
  const trimmed = input.trim();
  const empty: PhoneCheckResult = {
    input: trimmed,
    valid: false,
    possible: false,
    country: undefined,
    countryCallingCode: undefined,
    type: undefined,
    e164: undefined,
    international: undefined,
    national: undefined,
  };

  try {
    const phone = parsePhoneNumber(trimmed);
    return {
      input: trimmed,
      valid: phone.isValid(),
      possible: phone.isPossible(),
      country: phone.country,
      countryCallingCode: phone.countryCallingCode,
      type: phone.getType(),
      e164: phone.number,
      international: phone.formatInternational(),
      national: phone.formatNational(),
    };
  } catch {
    return empty;
  }
}
