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
}

export class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[ErrorBoundary]", error, info.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;
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
