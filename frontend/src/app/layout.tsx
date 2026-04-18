// Root layout — required by Next.js App Router.
//
// This file is intentionally minimal. All real layout work (HTML attributes,
// fonts, providers, i18n) lives in app/[locale]/layout.tsx so that the
// locale parameter from the URL segment is available there.
//
// Do NOT add <html> or <body> here — [locale]/layout.tsx owns those tags.

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
