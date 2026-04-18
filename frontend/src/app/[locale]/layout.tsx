import type { Metadata } from "next";
import "../globals.css";
import { Providers } from "@/components/Providers";
import { Toaster } from "react-hot-toast";
import { NextIntlClientProvider } from "next-intl";
import { getMessages, getLocale } from "next-intl/server";
import { notFound } from "next/navigation";
import { locales } from "@/i18n/request";
import { ThemeProvider } from "next-themes";
import ThemeWrapper from "@/components/ThemeWrapper";


export const metadata: Metadata = {
  title: "PhishGuard — Cybersecurity Detection Platform",
  description:
    "Enterprise-grade phishing, fraud, and malicious URL detection powered by AI",
};

// ---------------------------------------------------------------------------
// [locale] layout
// ---------------------------------------------------------------------------
// Receives the locale from the URL segment (e.g. /en/dashboard → locale="en").
// Validates it, loads messages, and wires up NextIntlClientProvider so that
// all client components can use useTranslations() / useLocale().
// ---------------------------------------------------------------------------

export default async function LocaleLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: { locale: string };
}) {
  const { locale } = params;

  // Guard: reject unknown locale values with a 404
  if (!(locales as readonly string[]).includes(locale)) {
    notFound();
  }

  // getMessages() reads the locale that request.ts resolved — which is the
  // same URL segment locale validated above.
  const messages = await getMessages();

  return (
    <html lang={locale}>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        {/* Core UI fonts */}
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&family=Space+Grotesk:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600&display=swap"
          rel="stylesheet"
        />
        {/* Load Devanagari font only for Hindi */}
        {locale === "hi" && (
          <link
            href="https://fonts.googleapis.com/css2?family=Noto+Sans+Devanagari:wght@300;400;500;600;700&display=swap"
            rel="stylesheet"
          />
        )}
      </head>
      <body

        className={
          locale === "hi"
            ? "font-devanagari"
            : ""
        }
      >
        <ThemeWrapper>
          <NextIntlClientProvider locale={locale} messages={messages}>
            <Providers>
              {children}
              <Toaster
                position="top-right"
                toastOptions={{
                  style: {
                    background: "#0c1120",
                    color: "#e8eaf0",
                    border: "1px solid #1a2540",
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: "13px",
                  },
                  success: {
                    iconTheme: { primary: "#00ff88", secondary: "#0c1120" },
                  },
                  error: {
                    iconTheme: { primary: "#ff2d55", secondary: "#0c1120" },
                  },
                }}
              />
            </Providers>
          </NextIntlClientProvider>
        </ThemeWrapper>
      </body>
    </html>
  );
}
