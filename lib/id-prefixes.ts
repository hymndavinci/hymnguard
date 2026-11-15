// Offline Indonesian mobile-operator prefix table.
//
// Mobile numbers in Indonesia start with a 4-digit operator prefix
// (domestic form 08XX). The prefix shows which operator the number was
// ALLOCATED to; the current operator can differ if the number was ported,
// so the UI says so.
//
// Source: Indonesian Wikipedia, "Daftar kode telepon di Indonesia"
// (https://id.wikipedia.org/wiki/Daftar_kode_telepon_di_Indonesia),
// cross-checked against sent.dm's Indonesia numbering guide, sender.id's
// prefix list, and fastpay.co.id. Verified 2026-11-15.
//
// Notes:
// - XL, Axis, and Smartfren now sit under the merged XLSMART group, but
//   users know the brands, so the table reports brands.
// - Tri (3) is an Indosat Ooredoo Hutchison brand since the 2022 merger.
// - 0859 is shared by XL and Axis.
// - 0825 / 0827 / 0828 / 0829 are defunct allocations (Bakrie Telecom,
//   Net1/Ceria) with no current operator — deliberately NOT in the table,
//   so they report as an unknown prefix rather than a dead operator.
// - 0868 is PSN/ACeS satellite (ByRU), not a regular mobile operator.

export interface IdOperator {
  /** 4-digit domestic prefix, e.g. "0812". */
  prefix: string;
  /** Brand the user knows: Telkomsel, Indosat, Tri, XL, Axis, Smartfren. */
  operator: string;
  /** Parent company, when it differs from the brand. */
  parent?: string;
}

const PREFIXES: Record<string, IdOperator> = {
  // Telkomsel
  "0811": { prefix: "0811", operator: "Telkomsel" },
  "0812": { prefix: "0812", operator: "Telkomsel" },
  "0813": { prefix: "0813", operator: "Telkomsel" },
  "0821": { prefix: "0821", operator: "Telkomsel" },
  "0822": { prefix: "0822", operator: "Telkomsel" },
  "0823": { prefix: "0823", operator: "Telkomsel" },
  "0851": { prefix: "0851", operator: "Telkomsel" },
  "0852": { prefix: "0852", operator: "Telkomsel" },
  "0853": { prefix: "0853", operator: "Telkomsel" },
  // Indosat Ooredoo Hutchison
  "0814": { prefix: "0814", operator: "Indosat" },
  "0815": { prefix: "0815", operator: "Indosat" },
  "0816": { prefix: "0816", operator: "Indosat" },
  "0855": { prefix: "0855", operator: "Indosat" },
  "0856": { prefix: "0856", operator: "Indosat" },
  "0857": { prefix: "0857", operator: "Indosat" },
  "0858": { prefix: "0858", operator: "Indosat" },
  // Tri (Indosat brand)
  "0895": { prefix: "0895", operator: "Tri", parent: "Indosat" },
  "0896": { prefix: "0896", operator: "Tri", parent: "Indosat" },
  "0897": { prefix: "0897", operator: "Tri", parent: "Indosat" },
  "0898": { prefix: "0898", operator: "Tri", parent: "Indosat" },
  "0899": { prefix: "0899", operator: "Tri", parent: "Indosat" },
  // XL (XLSMART)
  "0817": { prefix: "0817", operator: "XL", parent: "XLSMART" },
  "0818": { prefix: "0818", operator: "XL", parent: "XLSMART" },
  "0819": { prefix: "0819", operator: "XL", parent: "XLSMART" },
  "0859": { prefix: "0859", operator: "XL / Axis", parent: "XLSMART" },
  "0877": { prefix: "0877", operator: "XL", parent: "XLSMART" },
  "0878": { prefix: "0878", operator: "XL", parent: "XLSMART" },
  "0879": { prefix: "0879", operator: "XL", parent: "XLSMART" },
  // Axis (XLSMART)
  "0831": { prefix: "0831", operator: "Axis", parent: "XLSMART" },
  "0832": { prefix: "0832", operator: "Axis", parent: "XLSMART" },
  "0833": { prefix: "0833", operator: "Axis", parent: "XLSMART" },
  "0838": { prefix: "0838", operator: "Axis", parent: "XLSMART" },
  // Smartfren (XLSMART)
  "0881": { prefix: "0881", operator: "Smartfren", parent: "XLSMART" },
  "0882": { prefix: "0882", operator: "Smartfren", parent: "XLSMART" },
  "0883": { prefix: "0883", operator: "Smartfren", parent: "XLSMART" },
  "0884": { prefix: "0884", operator: "Smartfren", parent: "XLSMART" },
  "0885": { prefix: "0885", operator: "Smartfren", parent: "XLSMART" },
  "0886": { prefix: "0886", operator: "Smartfren", parent: "XLSMART" },
  "0887": { prefix: "0887", operator: "Smartfren", parent: "XLSMART" },
  "0888": { prefix: "0888", operator: "Smartfren", parent: "XLSMART" },
  "0889": { prefix: "0889", operator: "Smartfren", parent: "XLSMART" },
  // PSN/ACeS satellite
  "0868": { prefix: "0868", operator: "PSN (satellite)" },
};

/**
 * Look up the operator for an Indonesian number from its prefix.
 * Accepts E.164 (+62...) or national (08...) form. Returns null for
 * non-Indonesian numbers and for prefixes not in the table (landlines,
 * defunct allocations, unallocated ranges).
 */
export function lookupIdOperator(input: string): IdOperator | null {
  const digits = input.trim().replace(/^\+/, "");
  let national: string;
  if (digits.startsWith("62")) {
    national = `0${digits.slice(2)}`;
  } else if (digits.startsWith("0")) {
    national = digits;
  } else {
    return null;
  }
  if (!national.startsWith("08")) return null;
  return PREFIXES[national.slice(0, 4)] ?? null;
}
