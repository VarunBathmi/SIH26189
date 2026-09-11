import React, { useState } from 'react'

const TABS = ['Centrality', 'Communities', 'Anomalies', 'Link Predictions', 'Path Finder', 'Timeline', 'Audit Log']

export default function AnalysisPanel({
  caseId, entities, centrality, communities, anomalies, linkPredictions,
  pathResult, onRunPath, log, onSelectEntity, timeline, onLoadTimeline, timelineEntityFilter,
}) {
  const [active, setActive] = useState('Centrality')
  const [source, setSource] = useState('')
  const [target, setTarget] = useState('')
  const [timelineFilter, setTimelineFilter] = useState('')

  const handleTabClick = (t) => {
    setActive(t)
    if (t === 'Timeline') onLoadTimeline(timelineFilter || null)
  }

  const handleTimelineFilterChange = (id) => {
    setTimelineFilter(id)
    onLoadTimeline(id || null)
  }

  const KIND_ICON = {
    call: '📞', chat: '💬', browser_history: '🌐', file_artifact: '📁', location_ping: '📍',
  }

  if (!caseId) {
    return (
      <div className="panel">
        <div className="tabs">
          {TABS.map(t => <button key={t} className="tab">{t}</button>)}
        </div>
        <div className="panel-body">
          <div className="empty-state">Load a case to run analysis.</div>
        </div>
      </div>
    )
  }

  return (
    <div className="panel">
      <div className="tabs">
        {TABS.map(t => (
          <button
            key={t}
            className={`tab ${active === t ? 'active' : ''}`}
            onClick={() => handleTabClick(t)}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="panel-body">
        {active === 'Centrality' && (
          <>
            <div className="section-label">Ranked by betweenness — likely intermediaries/brokers</div>
            {centrality.map(row => (
              <div className="entity-row" key={row.entity_id} onClick={() => onSelectEntity(row.entity_id)}>
                <span className="name">{row.name}</span>
                <span className="metric">{row.betweenness_centrality}</span>
              </div>
            ))}
          </>
        )}

        {active === 'Communities' && (
          <>
            <div className="section-label">Detected clusters — {communities.length} group{communities.length !== 1 ? 's' : ''}</div>
            {communities.map(c => (
              <div className="community-block" key={c.community_id}>
                <div className="head">
                  <span>Cluster {c.community_id + 1}</span>
                  <span>{c.size} entities</span>
                </div>
                <div className="members">
                  {c.members.map(m => m.name).join(', ')}
                </div>
              </div>
            ))}
          </>
        )}

        {active === 'Anomalies' && (
          <>
            <div className="section-label">Triage signal only — not a determination of involvement</div>
            {anomalies.map(row => (
              <div className="entity-row" key={row.entity_id} onClick={() => onSelectEntity(row.entity_id)}>
                <span className="name">{row.name}</span>
                <span className={`metric ${row.anomaly_score > 0.6 ? 'danger' : ''}`}>
                  {row.anomaly_score}
                </span>
              </div>
            ))}
          </>
        )}

        {active === 'Link Predictions' && (
          <>
            <div className="section-label">Probable but unconfirmed connections (Adamic-Adar)</div>
            {linkPredictions.map((p, i) => (
              <div className="entity-row" key={i}>
                <span className="name">{p.entity_a_name} ↔ {p.entity_b_name}</span>
                <span className="metric">{p.predicted_score}</span>
              </div>
            ))}
          </>
        )}

        {active === 'Path Finder' && (
          <>
            <div className="section-label">Trace how two entities are connected</div>
            <div className="path-form">
              <select value={source} onChange={e => setSource(e.target.value)}>
                <option value="">Select source entity</option>
                {entities.map(e => <option key={e.id} value={e.id}>{e.name}</option>)}
              </select>
              <select value={target} onChange={e => setTarget(e.target.value)}>
                <option value="">Select target entity</option>
                {entities.map(e => <option key={e.id} value={e.id}>{e.name}</option>)}
              </select>
              <button
                className="btn btn-primary"
                disabled={!source || !target}
                onClick={() => onRunPath(source, target)}
              >
                Trace path
              </button>
            </div>
            {pathResult && (
              <div className="path-result">
                {pathResult.error ? (
                  <span style={{ color: 'var(--danger)' }}>{pathResult.error}</span>
                ) : (
                  <>
                    <div>{pathResult.length} hop{pathResult.length !== 1 ? 's' : ''} apart</div>
                    <div className="path-chain">
                      {pathResult.path_names.map((n, i) => (
                        <React.Fragment key={i}>
                          <span>{n}</span>
                          {i < pathResult.path_names.length - 1 && <span>→</span>}
                        </React.Fragment>
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}
          </>
        )}

        {active === 'Timeline' && (
          <>
            <div className="section-label">Chronological event feed across all artifact types</div>
            <select
              value={timelineFilter}
              onChange={e => handleTimelineFilterChange(e.target.value)}
              style={{
                background: 'var(--panel-raised)', border: '1px solid var(--border)',
                color: 'var(--text)', padding: 8, borderRadius: 4, fontSize: 12.5,
                width: '100%', marginBottom: 10,
              }}
            >
              <option value="">All entities</option>
              {entities.map(e => <option key={e.id} value={e.id}>{e.name}</option>)}
            </select>
            {timeline.length === 0 && <div className="empty-state">No events.</div>}
            {timeline.map((ev, i) => (
              <div className="log-entry" key={i} style={{ fontFamily: 'var(--font-ui)', fontSize: 12.5, color: 'var(--text)' }}>
                <span style={{ marginRight: 6 }}>{KIND_ICON[ev.type] || '•'}</span>
                {ev.summary}
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>
                  {new Date(ev.timestamp).toLocaleString()}
                </div>
              </div>
            ))}
          </>
        )}

        {active === 'Audit Log' && (
          <>
            <div className="section-label">Chain-of-custody — every analytical action logged</div>
            {log.slice().reverse().map(entry => (
              <div className="log-entry" key={entry.log_id}>
                <span className="action">{entry.action}</span> · {new Date(entry.timestamp).toLocaleTimeString()}
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  )
}
