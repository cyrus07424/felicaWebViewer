import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Script from "next/script";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: 'FeliCa Web Viewer',
  description: 'RC-S380 を使用して FeliCa カードの情報を読み取る Web アプリ',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const gtmContainerId = process.env.NEXT_PUBLIC_GTM_CONTAINER_ID;
  const validGtmContainerId =
    gtmContainerId && /^GTM-[A-Z0-9]{7,8}$/.test(gtmContainerId)
      ? gtmContainerId
      : null;

  return (
    <html lang="ja">
      {validGtmContainerId ? (
        <>
          <Script id="gtm-data-layer" strategy="beforeInteractive">
            {`window.dataLayer = window.dataLayer || [];window.dataLayer.push({'gtm.start': new Date().getTime(), event: 'gtm.js'});`}
          </Script>
          <Script
            id="gtm-loader"
            src={`https://www.googletagmanager.com/gtm.js?id=${validGtmContainerId}`}
            strategy="beforeInteractive"
          />
        </>
      ) : null}
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {validGtmContainerId ? (
          <noscript>
            <iframe
              src={`https://www.googletagmanager.com/ns.html?id=${validGtmContainerId}`}
              height="0"
              width="0"
              style={{ display: "none", visibility: "hidden" }}
            />
          </noscript>
        ) : null}
        {children}
      </body>
    </html>
  );
}
