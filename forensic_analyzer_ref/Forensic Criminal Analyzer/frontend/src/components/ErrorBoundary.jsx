import React from 'react'

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, message: '' }
  }

  static getDerivedStateFromError(err) {
    return { hasError: true, message: err?.message || 'Something went wrong.' }
  }

  componentDidCatch(err, info) {
    // eslint-disable-next-line no-console
    console.error('Forensic Criminal Analyzer crashed:', err, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          height: '100vh', display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', gap: 12,
          background: 'var(--bg)', color: 'var(--text)', padding: 24, textAlign: 'center',
        }}>
          <h2 style={{ color: 'var(--danger)' }}>Something went wrong</h2>
          <p style={{ color: 'var(--text-muted)', maxWidth: 420, fontSize: 13 }}>
            {this.state.message}
          </p>
          <button className="btn btn-primary" onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
