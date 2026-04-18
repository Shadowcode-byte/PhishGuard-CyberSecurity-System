import { defineRouting } from "next-intl/routing";

// ---------------------------------------------------------------------------
// WHY localePrefix: "as-needed"
// ---------------------------------------------------------------------------
// "never"      → no locale in URL; locale is cookie-only.
//                Side effect: /en returns 404 because middleware never
//                strips the /en prefix before handing to Next.js, so the
//                router finds no matching [locale] segment.
//
// "always"     → every URL has a prefix, including the default locale.
//                / → 302 → /en  (extra redirect for English users)
//
// "as-needed"  → default locale (en) served at / with NO prefix.
//                Non-default locale (hi) served at /hi/*.
//                /en also works and normalises to /.
//
//   /           → English landing page  (no redirect)
//   /en         → English landing page  (normalised, works)
//   /hi         → Hindi landing page
//   /dashboard  → English dashboard
//   /hi/dashboard → Hindi dashboard
// ---------------------------------------------------------------------------

export const routing = defineRouting({
  locales: ["en", "hi"],
  defaultLocale: "en",
  localePrefix: "as-needed",
});
