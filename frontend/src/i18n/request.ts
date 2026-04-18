import { getRequestConfig } from "next-intl/server";
import { routing } from "./routing";

// ---------------------------------------------------------------------------
// Supported locales
// ---------------------------------------------------------------------------
export const locales = ["en", "hi"] as const;
export type Locale = (typeof locales)[number];
export const defaultLocale: Locale = "en";

// ---------------------------------------------------------------------------
// WHY requestLocale instead of cookies()
// ---------------------------------------------------------------------------
// The previous implementation read the locale from the NEXT_LOCALE cookie.
// This caused the Hindi→English switch to break because:
//   1. LanguageSwitcher navigated to /dashboard (no locale prefix = English)
//   2. But getRequestConfig still read the stale "hi" cookie
//   3. Result: URL said English, page rendered Hindi
//
// The correct next-intl v3 pattern is to use `requestLocale` — a promise
// that resolves to the locale extracted from the URL path by the middleware
// (set via the x-next-intl-locale request header).  This is always in sync
// with the URL, so switching locale by navigating to a different path works
// in both directions without any cookie.
// ---------------------------------------------------------------------------

type MessageLoader = () => Promise<{ default: Record<string, unknown> }>;

const messageLoaders: Record<Locale, MessageLoader> = {
  en: () => import("../messages/en.json"),
  hi: () => import("../messages/hi.json"),
};

export default getRequestConfig(async ({ requestLocale }) => {
  // requestLocale is set by next-intl middleware from the URL path.
  // Await it, then validate — fall back to English for unknown values.
  const requested = await requestLocale;

  const locale: Locale =
    requested && (locales as readonly string[]).includes(requested)
      ? (requested as Locale)
      : defaultLocale;

  const loader = messageLoaders[locale] ?? messageLoaders[defaultLocale];
  const messages = await loader()
    .then((m) => m.default)
    .catch(async () => (await messageLoaders[defaultLocale]()).default);

  return { locale, messages };
});
