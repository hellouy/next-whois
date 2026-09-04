import type { NextPageContext } from "next";
import Head from "next/head";
import Link from "next/link";
import { RiAlertLine } from "@remixicon/react";
import { siteTitle } from "@/lib/seo";

interface ErrorProps {
  statusCode?: number;
  message?: string;
}

function ErrorPage({ statusCode, message }: ErrorProps) {
  const title =
    statusCode === 404
      ? "Page Not Found"
      : statusCode === 500
      ? "Server Error"
      : "An Error Occurred";

  const desc =
    statusCode === 404
      ? "The page you're looking for doesn't exist."
      : statusCode === 500
      ? "An internal server error occurred. Please try again later."
      : message || "Something went wrong. Please try again.";

  return (
    <>
      <Head>
        <title>{`${statusCode ?? "Error"} – ${siteTitle}`}</title>
      </Head>
      <div className="flex flex-col items-center justify-center min-h-[60vh] px-4 text-center">
        <div className="w-14 h-14 rounded-2xl bg-red-50 dark:bg-red-950/30 flex items-center justify-center mb-5">
          <RiAlertLine className="w-7 h-7 text-red-500" />
        </div>
        {statusCode && (
          <p className="text-4xl font-bold text-foreground mb-2">{statusCode}</p>
        )}
        <h1 className="text-lg font-semibold text-foreground mb-2">{title}</h1>
        <p className="text-sm text-muted-foreground max-w-sm mb-6">{desc}</p>
        <Link
          href="/"
          className="text-sm font-medium text-primary hover:underline underline-offset-4"
        >
          ← Back to Home
        </Link>
      </div>
    </>
  );
}

ErrorPage.getInitialProps = ({ res, err, req }: NextPageContext): ErrorProps => {
  const statusCode = res?.statusCode ?? err?.statusCode ?? 500;
  if (err && typeof window !== "undefined") {
    // SSR-render errors: report client-side once hydration finishes
    void import("@sentry/nextjs").then(Sentry => {
      if (process.env.NEXT_PUBLIC_SENTRY_DSN) {
        Sentry.captureException(err);
      }
    }).catch(() => {});
  } else if (err) {
    void import("@/lib/monitoring-server").then(m => m.captureException(err, { req: req?.url })).catch(() => {});
  }
  return { statusCode };
};

export default ErrorPage;
