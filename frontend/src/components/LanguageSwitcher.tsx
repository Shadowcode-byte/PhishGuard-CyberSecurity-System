"use client";

import { useLocale } from "next-intl";
import { useRouter, usePathname } from "next/navigation";
import { useTransition } from "react";
import { Globe } from "lucide-react";

// ---------------------------------------------------------------------------
// LanguageSwitcher
// ---------------------------------------------------------------------------
// Locale switching is URL-based (/en/... and /hi/... paths) using next-intl
// with localePrefix: "as-needed".  This means:
//
//   English (default locale) → no prefix  →  /dashboard
//   Hindi                    → /hi prefix  →  /hi/dashboard
//
// FIX — Two bugs were present:
//
//   Bug A (race condition): router.refresh() was called immediately after
//   router.push() inside startTransition, causing the refresh to fire before
//   the navigation completed.  Fix: remove the extra router.refresh() —
//   next-intl re-renders automatically when the URL locale segment changes.
//
//   Bug B (localStorage not persisted): language preference was written only
//   to a cookie.  We now also write to localStorage so client components that
//   read localStorage for locale preference stay in sync.
// ---------------------------------------------------------------------------

const LOCALES = ["en", "hi"] as const;

function stripLocalePrefix(path: string): string {
  // Remove any leading /<locale> segment where <locale> is a known locale.
  // e.g. "/hi/dashboard" → "/dashboard"
  //      "/dashboard"    → "/dashboard"
  //      "/en/foo"       → "/foo"
  for (const locale of LOCALES) {
    if (path === `/${locale}`) return "/";
    if (path.startsWith(`/${locale}/`)) return path.slice(`/${locale}`.length);
  }
  return path;
}

export function LanguageSwitcher() {
  const locale = useLocale();
  const router = useRouter();
  const pathname = usePathname();
  const [isPending, startTransition] = useTransition();

  const switchLocale = (next: string) => {
    if (next === locale) return;

    // 1. Strip any existing locale prefix from the current path.
    const stripped = stripLocalePrefix(pathname);

    // 2. Build the new path.
    //    English is the default locale → no prefix (localePrefix: "as-needed").
    //    Hindi → /hi<path>.
    const nextPath = next === "en" ? stripped : `/${next}${stripped}`;

    // 3. Persist language preference to both localStorage and cookie so:
    //    - Client components reading localStorage stay in sync.
    //    - Legacy server components reading NEXT_LOCALE cookie stay in sync.
    try {
      localStorage.setItem("lang", next);
    } catch (_) {
      // localStorage may be unavailable in some privacy modes — ignore
    }
    document.cookie = `NEXT_LOCALE=${next}; path=/; max-age=31536000; SameSite=Lax`;

    // 4. Navigate to the new locale path.
    //    FIX: Do NOT call router.refresh() here — it races with router.push()
    //    and can cancel the navigation, causing Hindi→English to silently fail.
    //    next-intl middleware re-renders server components automatically when
    //    the URL locale changes.
    startTransition(() => {
      router.push(nextPath);
    });
  };

  return (
    <div
      className="flex items-center gap-1 px-2 py-1.5 rounded-lg border"
      style={{
        borderColor: "rgba(0,245,255,0.2)",
        background: "rgba(0,245,255,0.04)",
      }}
      title="Switch language"
    >
      <Globe
        className="w-3.5 h-3.5 shrink-0"
        style={{ color: "#00f5ff", opacity: isPending ? 0.4 : 1 }}
      />
      <button
        onClick={() => switchLocale("en")}
        disabled={isPending}
        className="text-xs font-mono transition-colors px-1"
        style={{
          color: locale === "en" ? "#00f5ff" : "#8892b0",
          fontWeight: locale === "en" ? 600 : 400,
          cursor: isPending ? "not-allowed" : "pointer",
          background: "none",
          border: "none",
          padding: "0 4px",
        }}
        aria-label="Switch to English"
        aria-pressed={locale === "en"}
      >
        EN
      </button>
      <span style={{ color: "#1a2540", fontSize: "10px" }}>|</span>
      <button
        onClick={() => switchLocale("hi")}
        disabled={isPending}
        className="text-xs font-mono transition-colors px-1"
        style={{
          color: locale === "hi" ? "#00f5ff" : "#8892b0",
          fontWeight: locale === "hi" ? 600 : 400,
          cursor: isPending ? "not-allowed" : "pointer",
          background: "none",
          border: "none",
          padding: "0 4px",
          fontFamily:
            locale === "hi"
              ? "'Noto Sans Devanagari', sans-serif"
              : "inherit",
        }}
        aria-label="हिंदी में बदलें"
        aria-pressed={locale === "hi"}
      >
        हि
      </button>
    </div>
  );
}
