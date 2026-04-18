import createMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";

// ---------------------------------------------------------------------------
// next-intl middleware
// ---------------------------------------------------------------------------
// With localePrefix: "as-needed":
//
//   GET /          → locale=en, no URL change (default locale, no prefix)
//   GET /en        → locale=en, redirects to /  (strip redundant prefix)
//   GET /hi        → locale=hi, no URL change
//   GET /dashboard → locale=en (default), no URL change
//   GET /hi/dashboard → locale=hi, no URL change
//
// The middleware injects x-next-intl-locale into request headers so that
// getRequestConfig can read it via requestLocale without cookies.
// ---------------------------------------------------------------------------

export default createMiddleware(routing);

export const config = {
  // Run on every path EXCEPT:
  //   _next/*       Next.js build assets
  //   api/*         API route handlers (must not be locale-prefixed)
  //   *.ext         Static files (favicon.ico, images, etc.)
  //
  // The root "/" must also be matched (handled by the second pattern).
  matcher: [
    "/((?!_next|api|[^/]*\\.[^/]*).*)",
    "/",
  ],
};
