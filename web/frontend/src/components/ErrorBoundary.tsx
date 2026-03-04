/* ErrorBoundary – catches render errors and shows fallback UI */

import { Component, type ReactNode, type ErrorInfo } from "react";

interface Props {
  children: ReactNode;
  fallbackLabel?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[ErrorBoundary]", error, info);
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <div className="error-boundary__icon">⚠</div>
          <div className="error-boundary__title">
            {this.props.fallbackLabel ?? "Bir hata oluştu"}
          </div>
          <div className="error-boundary__message">
            {this.state.error?.message}
          </div>
          <button className="btn btn--secondary error-boundary__retry" onClick={this.handleRetry}>
            Tekrar Dene
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
