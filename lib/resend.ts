// Resend email sending (shared by signup codes, password resets, and
// breach-monitoring alerts). POST https://api.resend.com/emails.
//
// The free tier only sends from onboarding@resend.dev to the account
// owner's own address; sending to arbitrary emails requires a verified
// domain (set RESEND_FROM to an address on it).

const FETCH_TIMEOUT_MS = 8000;

export interface SendEmailOptions {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export interface SendEmailResult {
  ok: boolean;
  error?: string;
}

export function isResendConfigured(): boolean {
  return Boolean(process.env.RESEND_API_KEY && process.env.RESEND_FROM);
}

export async function sendEmail(
  options: SendEmailOptions,
  apiKey: string,
  from: string,
): Promise<SendEmailResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: [options.to],
        subject: options.subject,
        text: options.text,
        html: options.html,
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      return {
        ok: false,
        error: `Resend responded with HTTP ${res.status}${body ? `: ${body.slice(0, 200)}` : ""}`,
      };
    }
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error && err.name === "AbortError"
          ? "Resend request timed out"
          : "Could not reach Resend",
    };
  } finally {
    clearTimeout(timer);
  }
}
