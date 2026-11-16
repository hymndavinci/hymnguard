// GitHub exposure (Gitrecon-style): search PUBLIC commits for the email
// as an author address. People often commit with a personal email, which
// exposes the address — and its association with their GitHub identity —
// in public git history.
//
// Requires GITHUB_TOKEN (any token with no scopes works for public commit
// search). The caller reports a needs-key state when unset. Search API rate
// limit for authenticated requests is 30/min; one call per email check.
//
// Only public data is shown: repo name, author name, date, and the first
// line of the commit message (truncated). Commit SHAs and author emails are
// not needed in the UI.

const USER_AGENT = "HymnGuard";
const FETCH_TIMEOUT_MS = 8000;
const MAX_COMMITS = 10;

export interface GitHubCommitExposure {
  repo: string;
  authorName: string;
  date: string;
  message: string;
  url: string;
}

export type GitHubExposureResult =
  | {
      status: "ok";
      total: number;
      commits: GitHubCommitExposure[];
      /** GitHub logins whose commits carry this email (dossier cross-refs). */
      logins: string[];
    }
  | { status: "rate_limited" }
  | { status: "error"; error: string };

/** GitHub logins whose public commits carry this email as the author
 *  address. Used by dossier username ownership (a login is proven yours
 *  when its public commits use an email you have already verified). */
export type GitHubAuthorLoginsResult =
  | { status: "ok"; logins: string[] }
  | { status: "rate_limited" }
  | { status: "error"; error: string };

interface CommitSearchItem {
  repository?: { full_name?: string };
  author?: { login?: string } | null;
  commit?: {
    author?: { name?: string; date?: string };
    message?: string;
  };
  html_url?: string;
}

type CommitSearchResult =
  | { status: "ok"; total: number; items: CommitSearchItem[] }
  | { status: "rate_limited" }
  | { status: "error"; error: string };

async function fetchCommitSearch(
  email: string,
  token: string,
): Promise<CommitSearchResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(
      `https://api.github.com/search/commits?q=${encodeURIComponent(`author-email:${email}`)}&per_page=${MAX_COMMITS}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": USER_AGENT,
        },
        signal: controller.signal,
      },
    );
    if (res.status === 403) {
      const remaining = res.headers.get("x-ratelimit-remaining");
      if (remaining === "0") return { status: "rate_limited" };
      return {
        status: "error",
        error: "GitHub rejected the request (check the token)",
      };
    }
    if (res.status === 401) {
      return { status: "error", error: "GitHub token is invalid" };
    }
    if (res.status === 422) {
      return { status: "error", error: "GitHub could not run this query" };
    }
    if (!res.ok) {
      return {
        status: "error",
        error: `GitHub responded with HTTP ${res.status}`,
      };
    }
    const data = (await res.json()) as {
      total_count?: number;
      items?: CommitSearchItem[];
    };
    if (typeof data.total_count !== "number" || !Array.isArray(data.items)) {
      return {
        status: "error",
        error: "GitHub returned an unexpected response shape",
      };
    }
    return { status: "ok", total: data.total_count, items: data.items };
  } catch (err) {
    return {
      status: "error",
      error:
        err instanceof Error && err.name === "AbortError"
          ? "GitHub request timed out"
          : "Could not reach GitHub",
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function searchGitHubCommits(
  email: string,
  token: string,
): Promise<GitHubExposureResult> {
  const result = await fetchCommitSearch(email, token);
  if (result.status !== "ok") return result;
  const commits: GitHubCommitExposure[] = result.items
    .filter((item) => item.repository?.full_name)
    .map((item) => ({
      repo: item.repository?.full_name as string,
      authorName: item.commit?.author?.name ?? "—",
      date: item.commit?.author?.date ?? "",
      message: (item.commit?.message ?? "").split("\n")[0].slice(0, 80),
      url: item.html_url ?? "",
    }));
  const logins = [
    ...new Set(
      result.items
        .map((item) => item.author?.login)
        .filter((login): login is string => Boolean(login)),
    ),
  ];
  return { status: "ok", total: result.total, commits, logins };
}

export async function searchCommitAuthorLogins(
  email: string,
  token: string,
): Promise<GitHubAuthorLoginsResult> {
  const result = await fetchCommitSearch(email, token);
  if (result.status !== "ok") return result;
  const logins = [
    ...new Set(
      result.items
        .map((item) => item.author?.login)
        .filter((login): login is string => Boolean(login)),
    ),
  ];
  return { status: "ok", logins };
}
