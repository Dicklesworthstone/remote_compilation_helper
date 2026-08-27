import { Component, type ErrorInfo, type ReactNode } from "react";
import { clearKey } from "../crypto";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Uncaught error in dashboard:", error, info);
  }

  handleReset = () => {
    clearKey();
    localStorage.removeItem("rch_dash_key");
    location.reload();
  };

  override render() {
    if (this.state.error) {
      return (
        <div style={{ maxWidth: 480, margin: "64px auto", padding: "0 16px" }}>
          <div className="banner crit" style={{ display: "block" }}>
            <h3 style={{ margin: "0 0 8px" }}>Dashboard encountered a problem</h3>
            <p style={{ margin: "0 0 12px", fontSize: 13 }}>
              {this.state.error.message || "An unexpected error occurred."}
            </p>
            <button className="btn" onClick={this.handleReset}>
              Reset Session & Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
