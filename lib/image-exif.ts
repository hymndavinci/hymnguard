// Image metadata analysis — client-side only (exifr). The image file is
// parsed in the browser and NEVER leaves the device: there is no API
// route for this checker, no upload, no server call.
//
// What it surfaces: camera/device, software, timestamps, exposure
// settings, embedded thumbnail presence, and — the high-value exposure —
// GPS coordinates. A photo shared online can carry its exact shooting
// location; that is the finding this checker exists to surface.
//
// Verified locally 2026-11-15 with exifr 7.1.3: a JPEG with crafted EXIF
// (Make/Model/Software/DateTime/GPS) parses fully, including computed
// latitude/longitude; a stripped JPEG returns no metadata.

import exifr from "exifr";

/** Largest image accepted for analysis (20 MB). */
export const MAX_IMAGE_BYTES = 20 * 1024 * 1024;

export interface ImageGps {
  latitude: number;
  longitude: number;
}

export interface ImageExifResult {
  fileName: string;
  fileSize: number;
  fileType: string;
  /** True when the file carries any EXIF/XMP/IPTC metadata block. */
  hasExif: boolean;
  /** Flat display rows (label + value), in a stable order. */
  fields: { label: string; value: string }[];
  /** GPS coordinates when present — the main privacy exposure. */
  gps?: ImageGps;
  /** Device that took the photo, when recorded. */
  device?: string;
  /** When the photo was taken, when recorded. */
  dateTaken?: string;
  /** True when an embedded thumbnail is present in the metadata. */
  hasThumbnail: boolean;
}

type RawExif = Record<string, unknown>;

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function formatExposure(seconds: number): string {
  if (seconds <= 0) return String(seconds);
  if (seconds >= 1) return `${seconds}s`;
  return `1/${Math.round(1 / seconds)}s`;
}

function formatDate(value: unknown): string | undefined {
  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    return value.toISOString();
  }
  return asString(value);
}

/** Parses an image file entirely in the browser. Throws when the file is
 * not an image, is too large, or its metadata cannot be read. */
export async function analyzeImage(file: File): Promise<ImageExifResult> {
  if (!file.type.startsWith("image/")) {
    throw new Error("That file is not an image.");
  }
  if (file.size > MAX_IMAGE_BYTES) {
    throw new Error("That image is larger than 20 MB.");
  }

  let parsed: RawExif | undefined;
  try {
    parsed = (await exifr.parse(file, { gps: true })) as RawExif | undefined;
  } catch {
    throw new Error("Could not read metadata from this image.");
  }

  const fields: { label: string; value: string }[] = [];
  if (!parsed) {
    return {
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type,
      hasExif: false,
      fields,
      hasThumbnail: false,
    };
  }

  const make = asString(parsed.Make);
  const model = asString(parsed.Model);
  const device =
    make && model
      ? `${make} ${model}`
      : (make ?? model ?? undefined);
  const software = asString(parsed.Software);
  const dateTaken = formatDate(
    parsed.DateTimeOriginal ?? parsed.CreateDate ?? parsed.ModifyDate,
  );
  const latitude = asNumber(parsed.latitude);
  const longitude = asNumber(parsed.longitude);
  const gps =
    latitude !== undefined && longitude !== undefined
      ? { latitude, longitude }
      : undefined;

  // Exposure fields: exifr sometimes leaves these under numeric tag keys.
  const exposureTime = asNumber(parsed.ExposureTime ?? parsed["33434"]);
  const fNumber = asNumber(parsed.FNumber ?? parsed["33437"]);
  const iso = asNumber(parsed.ISO ?? parsed["34855"]);
  const focalLength = asNumber(parsed.FocalLength ?? parsed["37386"]);

  let hasThumbnail = false;
  try {
    const thumb = await exifr.thumbnail(file);
    hasThumbnail = thumb !== undefined && thumb !== null;
  } catch {
    hasThumbnail = false;
  }

  if (device) fields.push({ label: "Device", value: device });
  if (software) fields.push({ label: "Software", value: software });
  if (dateTaken) fields.push({ label: "Date taken", value: dateTaken });
  if (gps) {
    fields.push({
      label: "GPS coordinates",
      value: `${gps.latitude}, ${gps.longitude}`,
    });
  }
  if (exposureTime !== undefined) {
    fields.push({ label: "Exposure", value: formatExposure(exposureTime) });
  }
  if (fNumber !== undefined) {
    fields.push({ label: "Aperture", value: `f/${fNumber}` });
  }
  if (iso !== undefined) {
    fields.push({ label: "ISO", value: String(iso) });
  }
  if (focalLength !== undefined) {
    fields.push({ label: "Focal length", value: `${focalLength} mm` });
  }
  if (hasThumbnail) {
    fields.push({
      label: "Embedded thumbnail",
      value: "Present (a small copy of the photo is stored in the metadata)",
    });
  }

  return {
    fileName: file.name,
    fileSize: file.size,
    fileType: file.type,
    hasExif: true,
    fields,
    gps,
    device,
    dateTaken,
    hasThumbnail,
  };
}
