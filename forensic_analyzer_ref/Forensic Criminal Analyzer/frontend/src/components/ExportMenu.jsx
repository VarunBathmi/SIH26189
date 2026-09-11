import React, { useState, useRef, useEffect } from 'react'

const OPTIONS = [
  { key: 'report.pdf', label: 'Case report (PDF)' },
  { key: 'entities.csv', label: 'Entities (CSV)' },
  { key: 'artifacts.csv', label: 'Artifacts (CSV)' },
  { key: 'analysis.csv', label: 'Analysis scores (CSV)' },
]

export default function ExportMenu({ apiBase, caseId }) {
  const [open, setOpen] = useState(false)
  const ref = useRef()

  useEffect(() => {
    const onClick = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  const download = (key) => {
    const url = `${apiBase}/cases/${caseId}/export/${key}`
    const a = document.createElement('a')
    a.href = url
    a.download = ''
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    setOpen(false)
  }

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button className="btn" onClick={() => setOpen(o => !o)} style={{ width: '100%' }}>
        Export ▾
      </button>
      {open && (
        <div style={{
          position: 'absolute', top: '110%', left: 0, right: 0, zIndex: 20,
          background: 'var(--panel-raised)', border: '1px solid var(--border)',
          borderRadius: 4, overflow: 'hidden',
        }}>
          {OPTIONS.map(o => (
            <button
              key={o.key}
              onClick={() => download(o.key)}
              style={{
                display: 'block', width: '100%', textAlign: 'left', padding: '9px 12px',
                background: 'none', border: 'none', color: 'var(--text)', fontSize: 12.5,
                borderBottom: '1px solid var(--border)',
              }}
            >
              {o.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
