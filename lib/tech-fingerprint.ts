// Technology fingerprinting (Wappalyzer-style, free, no key).
// Fetches the homepage once and matches high-confidence markers in the
// headers and HTML: server software, CDN/hosting, CMS, and frameworks.
// Every detection carries its evidence string. Weak or ambiguous markers
// are deliberately left out — a missed technology is better than a wrong one.

const FETCH_TIMEOUT_MS = 5000;
const MAX_BODY_BYTES = 512 * 1024;
const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

export interface DetectedTech {
  name: string;
  category: "Server" | "CDN / Hosting" | "CMS" | "Framework" | "Library";
  evidence: string;
}

export interface TechResult {
  ok: boolean;
  error?: string;
  url?: string;
  technologies: DetectedTech[];
}

interface Marker {
  name: string;
  category: DetectedTech["category"];
  /** Test against the response headers (lowercase keys). */
  header?: (headers: Headers) => string | null;
  /** Test against the HTML body. */
  body?: (html: string) => string | null;
}

function headerContains(
  headers: Headers,
  key: string,
  needle: string,
): string | null {
  const value = headers.get(key);
  if (value && value.toLowerCase().includes(needle)) return `${key}: ${value}`;
  return null;
}

function bodyContains(html: string, needle: string): string | null {
  return html.includes(needle) ? `HTML contains "${needle}"` : null;
}

function bodyMatches(html: string, pattern: RegExp): string | null {
  const match = html.match(pattern);
  return match ? `HTML matches ${pattern}` : null;
}

const MARKERS: Marker[] = [
  // --- CDN / hosting (headers first — most reliable) ---
  {
    name: "Cloudflare",
    category: "CDN / Hosting",
    header: (h) =>
      headerContains(h, "cf-ray", "") ?? headerContains(h, "server", "cloudflare"),
  },
  {
    name: "Vercel",
    category: "CDN / Hosting",
    header: (h) => headerContains(h, "x-vercel-id", ""),
  },
  {
    name: "Amazon CloudFront",
    category: "CDN / Hosting",
    header: (h) => headerContains(h, "x-amz-cf-id", ""),
  },
  {
    name: "Fastly",
    category: "CDN / Hosting",
    header: (h) => headerContains(h, "x-served-by", "cache-"),
  },
  {
    name: "Akamai",
    category: "CDN / Hosting",
    header: (h) => headerContains(h, "x-akamai-request-id", ""),
  },
  {
    name: "Netlify",
    category: "CDN / Hosting",
    header: (h) => headerContains(h, "x-nf-request-id", ""),
  },
  {
    // The `server: github.com` header is sent by GitHub's own infrastructure
    // (github.com itself and GitHub Pages alike) — so this reports "GitHub",
    // not specifically GitHub Pages.
    name: "GitHub",
    category: "CDN / Hosting",
    header: (h) => headerContains(h, "server", "github.com"),
  },
  // --- Server software ---
  {
    name: "nginx",
    category: "Server",
    header: (h) => headerContains(h, "server", "nginx"),
  },
  {
    name: "Apache",
    category: "Server",
    header: (h) => headerContains(h, "server", "apache"),
  },
  {
    name: "LiteSpeed",
    category: "Server",
    header: (h) => headerContains(h, "server", "litespeed"),
  },
  {
    name: "Microsoft IIS",
    category: "Server",
    header: (h) =>
      headerContains(h, "server", "microsoft-iis") ??
      headerContains(h, "x-powered-by", "asp.net"),
  },
  {
    name: "Express",
    category: "Server",
    header: (h) => headerContains(h, "x-powered-by", "express"),
  },
  {
    name: "PHP",
    category: "Server",
    header: (h) => headerContains(h, "x-powered-by", "php"),
  },
  // --- CMS ---
  {
    name: "WordPress",
    category: "CMS",
    body: (html) =>
      bodyContains(html, "wp-content/") ?? bodyContains(html, "wp-includes/"),
  },
  {
    name: "Shopify",
    category: "CMS",
    body: (html) =>
      bodyContains(html, "cdn.shopify.com") ??
      bodyContains(html, "Shopify.theme"),
  },
  {
    name: "Wix",
    category: "CMS",
    body: (html) =>
      bodyContains(html, "wix.com") ?? bodyContains(html, "wix-static"),
  },
  {
    name: "Squarespace",
    category: "CMS",
    body: (html) => bodyContains(html, "squarespace.com"),
  },
  {
    name: "Webflow",
    category: "CMS",
    body: (html) =>
      bodyContains(html, "webflow") ?? bodyContains(html, "w-embed"),
  },
  {
    name: "Ghost",
    category: "CMS",
    body: (html) => bodyContains(html, "ghost/api"),
  },
  {
    name: "Drupal",
    category: "CMS",
    body: (html) =>
      bodyContains(html, "/sites/default/files") ??
      bodyContains(html, "drupal.js"),
  },
  {
    name: "Joomla",
    category: "CMS",
    body: (html) =>
      bodyContains(html, "/media/system/js/") ??
      bodyContains(html, "Joomla!"),
  },
  {
    name: "Magento",
    category: "CMS",
    body: (html) =>
      bodyContains(html, "Magento_") ?? bodyContains(html, "mage/cookies"),
  },
  {
    name: "MediaWiki",
    category: "CMS",
    body: (html) =>
      bodyContains(html, "mediawiki") ?? bodyContains(html, "mw-config"),
  },
  // --- Frameworks ---
  {
    name: "Next.js",
    category: "Framework",
    body: (html) =>
      bodyContains(html, "__NEXT_DATA__") ??
      bodyContains(html, "_next/static/"),
  },
  {
    name: "Nuxt",
    category: "Framework",
    body: (html) =>
      bodyContains(html, "__NUXT__") ?? bodyContains(html, "_nuxt/"),
  },
  {
    name: "Gatsby",
    category: "Framework",
    body: (html) =>
      bodyContains(html, "___gatsby") ?? bodyContains(html, "gatsby-"),
  },
  {
    name: "Angular",
    category: "Framework",
    body: (html) =>
      bodyContains(html, "ng-version=") ?? bodyContains(html, "<app-root"),
  },
  {
    name: "SvelteKit",
    category: "Framework",
    body: (html) => bodyContains(html, "sveltekit"),
  },
  {
    name: "Astro",
    category: "Framework",
    body: (html) =>
      bodyContains(html, "astro-island") ?? bodyContains(html, "Astro v"),
  },
  {
    name: "React",
    category: "Framework",
    body: (html) =>
      bodyMatches(html, /react-dom@\d|react@\d/) ??
      bodyContains(html, "data-reactroot"),
  },
  {
    name: "Vue.js",
    category: "Framework",
    body: (html) =>
      bodyContains(html, "vue@") ?? bodyContains(html, "__VUE__"),
  },
  {
    name: "Laravel",
    category: "Framework",
    header: (h) => headerContains(h, "set-cookie", "laravel_session"),
    body: (html) => bodyContains(html, "laravel"),
  },
  {
    name: "Django",
    category: "Framework",
    body: (html) =>
      bodyContains(html, "csrfmiddlewaretoken") ??
      bodyContains(html, "django.contrib"),
  },
  {
    name: "Ruby on Rails",
    category: "Framework",
    body: (html) => bodyContains(html, "csrf-param"),
  },
  // --- Libraries ---
  {
    name: "jQuery",
    category: "Library",
    body: (html) => bodyMatches(html, /jquery[-.][\d.]+(\.min)?\.js/i),
  },
  {
    name: "Bootstrap",
    category: "Library",
    body: (html) => bodyMatches(html, /bootstrap@\d|bootstrap(\.min)?\.(css|js)/i),
  },
  {
    name: "Tailwind CSS",
    category: "Library",
    body: (html) =>
      bodyContains(html, "cdn.tailwindcss.com") ??
      bodyContains(html, "tailwind.config"),
  },
];

/** <meta name="generator" content="..."> is a high-confidence CMS signal. */
function generatorTech(html: string): DetectedTech | null {
  const match = html.match(
    /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i,
  );
  const content = match?.[1]?.trim();
  if (!content) return null;
  const known: [RegExp, string, DetectedTech["category"]][] = [
    [/wordpress/i, "WordPress", "CMS"],
    [/hugo/i, "Hugo", "CMS"],
    [/jekyll/i, "Jekyll", "CMS"],
    [/ghost/i, "Ghost", "CMS"],
    [/drupal/i, "Drupal", "CMS"],
    [/joomla/i, "Joomla", "CMS"],
    [/shopify/i, "Shopify", "CMS"],
    [/next\.js/i, "Next.js", "Framework"],
    [/gatsby/i, "Gatsby", "Framework"],
    [/wix/i, "Wix", "CMS"],
    [/squarespace/i, "Squarespace", "CMS"],
  ];
  for (const [pattern, name, category] of known) {
    if (pattern.test(content)) {
      return {
        name,
        category,
        evidence: `meta generator: "${content}"`,
      };
    }
  }
  return null;
}

async function fetchHomepage(
  domain: string,
): Promise<{ url: string; headers: Headers; html: string } | null> {
  for (const scheme of ["https", "http"] as const) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(`${scheme}://${domain}/`, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: { "User-Agent": USER_AGENT },
      });
      const buffer = await res.arrayBuffer();
      const html = new TextDecoder("utf-8").decode(
        buffer.slice(0, MAX_BODY_BYTES),
      );
      return { url: res.url, headers: res.headers, html };
    } catch {
      // Fall through to the next scheme.
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

export function detectTechnologies(
  headers: Headers,
  html: string,
): DetectedTech[] {
  const found = new Map<string, DetectedTech>();
  for (const marker of MARKERS) {
    const evidence =
      marker.header?.(headers) ?? marker.body?.(html) ?? null;
    if (evidence && !found.has(marker.name)) {
      found.set(marker.name, {
        name: marker.name,
        category: marker.category,
        evidence,
      });
    }
  }
  const generator = generatorTech(html);
  if (generator && !found.has(generator.name)) {
    found.set(generator.name, generator);
  }
  return [...found.values()];
}

export async function fingerprintTech(domain: string): Promise<TechResult> {
  const page = await fetchHomepage(domain);
  if (!page) {
    return {
      ok: false,
      error: "Could not reach the site over HTTP or HTTPS",
      technologies: [],
    };
  }
  return {
    ok: true,
    url: page.url,
    technologies: detectTechnologies(page.headers, page.html),
  };
}
