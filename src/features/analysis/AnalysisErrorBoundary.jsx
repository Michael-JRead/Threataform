import { Component } from "react";

// ─────────────────────────────────────────────────────────────────────────────
// ANALYSIS ERROR BOUNDARY
// ─────────────────────────────────────────────────────────────────────────────
class AnalysisErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { err: null }; }
  static getDerivedStateFromError(e) { return { err: e }; }
  render() {
    if (this.state.err) {
      return (
        <div style={{ padding:32, color:"#EF5350", fontFamily:"monospace", fontSize:12, background:"#0C0C18", margin:24, borderRadius:6, border:"1px solid #EF535044" }}>
          <div style={{ fontWeight:700, marginBottom:8 }}>AnalysisPanel Error</div>
          <div>{String(this.state.err.message)}</div>
          <pre style={{ fontSize:10, color:"#666", marginTop:12, whiteSpace:"pre-wrap" }}>{this.state.err.stack}</pre>
        </div>
      );
    }
    return this.props.children;
  }
}

export default AnalysisErrorBoundary;
