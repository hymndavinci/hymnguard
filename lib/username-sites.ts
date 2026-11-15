// Curated username-probing site list, modelled on the detection approach of
// sherlock-project/sherlock (github.com/sherlock-project/sherlock).
// Each entry is probed with a single HTTP GET; detection is by status code,
// by a "not found" marker in the response body, or by the final URL after
// redirects. Implemented fresh in TypeScript — no Sherlock code is used.

export type SiteDetection = "status" | "message" | "response_url";

export interface UsernameSite {
  id: string;
  name: string;
  /** `{}` is replaced with the URL-encoded username. */
  urlTemplate: string;
  detection: SiteDetection;
  /**
   * When set, the probe request goes to this URL instead of the profile
   * URL (e.g. a public API or oEmbed endpoint), while the profile URL is
   * still the one shown in results. Modelled on Sherlock's `urlProbe`.
   */
  probeUrlTemplate?: string;
  /** Body markers that mean "this user does not exist" (message detection). */
  errorMarkers?: string[];
  /** Not found when the final URL equals this (trailing slash ignored). */
  errorUrlExact?: string;
  /** Not found when the final URL contains this substring. */
  errorUrlContains?: string;
  /** Extra HTTP statuses that mean "not found" for this site. */
  notFoundStatuses?: number[];
  /** Override the Accept header for this site (default is the HTML one). */
  accept?: string;
  /**
   * HTTP method for the probe (default GET). Sherlock's `request_method`.
   * POST sites send `requestPayload` as a JSON body.
   */
  method?: "GET" | "HEAD" | "POST";
  /** JSON body for POST probes. `{}` inside string values is replaced with the username. */
  requestPayload?: unknown;
  /** Extra headers for the probe (merged over the defaults). */
  headers?: Record<string, string>;
  /**
   * When set, the username must match this regex or the site is skipped
   * (reported as an error, never probed). Sherlock's `regexCheck`.
   */
  usernameRegex?: string;
  /**
   * For `response_url` detection: do not follow redirects; a 2xx response
   * means the account exists, anything else means it does not. This is
   * how Sherlock itself implements `response_url` (it disables redirects
   * and reads the status). Without this flag, `response_url` follows
   * redirects and compares the final URL against `errorUrlExact` /
   * `errorUrlContains` (the hand-tuned WordPress rule).
   */
  noRedirect?: boolean;
  /** Adult site (Sherlock's `isNSFW`). Shown with an 18+ badge in results. */
  isNSFW?: boolean;
}

/**
 * The 30 hand-verified sites from the MVP. Their rules were tuned and
 * verified individually and always win over the ported Sherlock list on
 * id collision — Sherlock's data supplements them, it never replaces them.
 */
export const CURATED_USERNAME_SITES: UsernameSite[] = [
  { id: "github", name: "GitHub", urlTemplate: "https://github.com/{}", detection: "status" },
  {
    id: "x",
    name: "X",
    urlTemplate: "https://x.com/{}",
    detection: "message",
    errorMarkers: ['<div class="error-panel"><span>User '],
  },
  {
    id: "hackernews",
    name: "Hacker News",
    urlTemplate: "https://news.ycombinator.com/user?id={}",
    detection: "message",
    errorMarkers: ["No such user."],
  },
  {
    id: "tiktok",
    name: "TikTok",
    urlTemplate: "https://www.tiktok.com/@{}",
    detection: "message",
    errorMarkers: ['"statusCode":10221'],
  },
  { id: "youtube", name: "YouTube", urlTemplate: "https://www.youtube.com/@{}", detection: "status" },
  { id: "linkedin", name: "LinkedIn", urlTemplate: "https://www.linkedin.com/in/{}", detection: "status" },
  {
    id: "pinterest",
    name: "Pinterest",
    urlTemplate: "https://www.pinterest.com/{}/",
    // The profile page is a JS shell that returns 200 either way; the
    // oEmbed endpoint returns 400 for a missing profile, 200 for a real one.
    probeUrlTemplate:
      "https://www.pinterest.com/oembed.json?url=https://www.pinterest.com/{}/",
    detection: "status",
    notFoundStatuses: [400],
  },
  { id: "snapchat", name: "Snapchat", urlTemplate: "https://www.snapchat.com/add/{}", detection: "status" },
  {
    id: "telegram",
    name: "Telegram",
    urlTemplate: "https://t.me/{}",
    detection: "message",
    errorMarkers: ["If you have <strong>Telegram</strong>, you can contact"],
  },
  {
    id: "twitch",
    name: "Twitch",
    urlTemplate: "https://www.twitch.tv/{}",
    detection: "message",
    errorMarkers: ["Twitch is the world&#39;s leading video platform"],
  },
  {
    id: "steam",
    name: "Steam",
    urlTemplate: "https://steamcommunity.com/id/{}",
    detection: "message",
    errorMarkers: ["The specified profile could not be found."],
  },
  { id: "flickr", name: "Flickr", urlTemplate: "https://www.flickr.com/people/{}", detection: "status" },
  { id: "vimeo", name: "Vimeo", urlTemplate: "https://vimeo.com/{}", detection: "status" },
  {
    id: "dribbble",
    name: "Dribbble",
    urlTemplate: "https://dribbble.com/{}",
    detection: "message",
    errorMarkers: ["Whoops, that page is gone."],
  },
  { id: "behance", name: "Behance", urlTemplate: "https://www.behance.net/{}", detection: "status" },
  { id: "gitlab", name: "GitLab", urlTemplate: "https://gitlab.com/{}", detection: "status" },
  { id: "codepen", name: "CodePen", urlTemplate: "https://codepen.io/{}", detection: "status" },
  { id: "patreon", name: "Patreon", urlTemplate: "https://www.patreon.com/{}", detection: "status" },
  {
    id: "deviantart",
    name: "DeviantArt",
    urlTemplate: "https://www.deviantart.com/{}",
    detection: "message",
    errorMarkers: ["Llama Not Found"],
  },
  { id: "soundcloud", name: "SoundCloud", urlTemplate: "https://soundcloud.com/{}", detection: "status" },
  { id: "wattpad", name: "Wattpad", urlTemplate: "https://www.wattpad.com/user/{}", detection: "status" },
  {
    id: "duolingo",
    name: "Duolingo",
    urlTemplate: "https://www.duolingo.com/profile/{}",
    // The profile page is a JS shell; the public users API returns
    // {"users":[]} for a missing username.
    probeUrlTemplate:
      "https://www.duolingo.com/2017-06-30/users?username={}",
    detection: "message",
    errorMarkers: ['{"users":[]}'],
  },
  { id: "gravatar", name: "Gravatar", urlTemplate: "https://en.gravatar.com/{}", detection: "status" },
  { id: "blogger", name: "Blogger", urlTemplate: "https://{}.blogspot.com", detection: "status" },
  {
    id: "wordpress",
    name: "WordPress.com",
    urlTemplate: "https://{}.wordpress.com/",
    detection: "response_url",
    errorUrlContains: "wordpress.com/typo/",
    notFoundStatuses: [410],
  },
  {
    id: "bluesky",
    name: "Bluesky",
    urlTemplate: "https://bsky.app/profile/{}.bsky.social",
    // The profile page is a JS shell; the public API returns 400
    // ("Profile not found") for a missing handle.
    probeUrlTemplate:
      "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social",
    detection: "status",
    notFoundStatuses: [400],
  },
  { id: "leetcode", name: "LeetCode", urlTemplate: "https://leetcode.com/{}", detection: "status" },
  {
    id: "hackerrank",
    name: "HackerRank",
    urlTemplate: "https://www.hackerrank.com/{}",
    detection: "message",
    errorMarkers: ["Something went wrong"],
  },
  { id: "codeforces", name: "Codeforces", urlTemplate: "https://codeforces.com/profile/{}", detection: "status" },
  {
    id: "kaggle",
    name: "Kaggle",
    urlTemplate: "https://www.kaggle.com/{}",
    detection: "status",
    // With an HTML Accept header Kaggle serves a reCAPTCHA challenge page
    // (200) to non-browser clients; with */* it answers 404/200 honestly.
    accept: "*/*",
  },
];

// Curated-site exclusions (see lib/username-sites-sherlock.ts for the
// ported-list exclusions, which are documented per site there):
// - Instagram: the profile page returns the same login wall (200) for real
//   and missing accounts, and the imginn mirror Sherlock probes returns 403.
//   No reliable free probe exists.
// - Spotify: the profile page is a JS shell returning 200 for any user id,
//   and the user API needs OAuth. No reliable free probe exists.
// - Reddit: profile pages are login-walled for unauthenticated requests,
//   and the JSON APIs (about.json, api.reddit.com) return 403. No reliable
//   free probe exists.

import { SHERLOCK_USERNAME_SITES } from "./username-sites-sherlock";

/**
 * The full site list: the 30 hand-tuned curated sites first, then the
 * verified Sherlock-ported sites. On id collision the curated rule wins
 * (the converter already skips those, so this is a safety net).
 */
export const USERNAME_SITES: UsernameSite[] = (() => {
  const seen = new Set<string>();
  const merged: UsernameSite[] = [];
  for (const site of [...CURATED_USERNAME_SITES, ...SHERLOCK_USERNAME_SITES]) {
    if (seen.has(site.id)) continue;
    seen.add(site.id);
    merged.push(site);
  }
  return merged;
})();
