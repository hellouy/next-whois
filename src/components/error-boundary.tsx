import React from "react";
import Link from "next/link";
import { RiAlertLine, RiRefreshLine } from "@remixicon/react";

interface Props {
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  autoRetrying: boolean;
}

// Webpack chunk-loading errors (require.e / __webpack_require__.e) are
// transient: they occur when the HMR runtime reloads the page before the
// webpack runtime has fully initialised.  A hard reload always fixes them.
function isWebpackChunkError(error: Error | null): boolean {
  if (!error) return false;
  const msg = error.message || "";
  return (
    msg.includes("require.e is not a function") ||
    msg.includes("__webpack_require__.e") ||
    msg.includes("ChunkLoadError") ||
    msg.includes("Loading chunk") ||
    msg.includes("chunkId")
  );
}

export class ErrorBoundary extends React.Component<Props, State> {
  private reloadTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null, autoRetrying: false };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error, autoRetrying: isWebpackChunkError(error) };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[ErrorBoundary]", error, info.componentStack);

    // Webpack chunk load failures are transient — silently reload the page.
    if (isWebpackChunkError(error)) {
      this.reloadTimer = setTimeout(() => {
        if (typeof window !== "undefined") window.location.reload();
      }, 1200);
    }
  }

  componentWillUnmount() {
    if (this.reloadTimer) clearTimeout(this.reloadTimer);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, autoRetrying: false });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      // Webpack chunk errors: show a minimal "reloading" message instead of
      // the scary error card, since a hard reload will fix them automatically.
      if (this.state.autoRetrying) {
        return (
          <div className="flex flex-col items-center justify-center min-h-[40vh] px-4 text-center gap-3">
            <div className="w-5 h-5 rounded-full border-2 border-primary/30 border-t-primary animate-spin" />
            <p className="text-sm text-muted-foreground">正在重新加载…</p>
          </div>
        );
      }

      return (
        <div className="flex flex-col items-center justify-center min-h-[40vh] px-4 text-center">
          <div className="w-14 h-14 rounded-2xl bg-red-50 dark:bg-red-950/30 flex items-center justify-center mb-5">
            <RiAlertLine className="w-7 h-7 text-red-500" />
          </div>
          <h2 className="text-lg font-semibold text-foreground mb-2">页面出现错误</h2>
          <p className="text-sm text-muted-foreground max-w-sm mb-6">
            {this.state.error?.message || "发生了意外错误，请刷新页面重试。"}
          </p>
          <div className="flex gap-3">
            <button
              onClick={this.handleReset}
              className="inline-flex items-center gap-1.5 text-sm font-medium text-primary hover:underline underline-offset-4"
            >
              <RiRefreshLine className="w-4 h-4" />
              重试
            </button>
            <span className="text-muted-foreground">·</span>
            <Link
              href="/"
              className="text-sm font-medium text-muted-foreground hover:text-foreground underline-offset-4"
            >
              返回首页
            </Link>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
