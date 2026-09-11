import React, { useState, useCallback, useRef } from 'react'
import axios from 'axios'
import GraphView from './components/GraphView.jsx'
import AnalysisPanel from './components/AnalysisPanel.jsx'
import ExportMenu from './components/ExportMenu.jsx'

// In production, set VITE_API_URL to the deployed backend's base URL
// (e.g. https://forensic-network-analyzer-api.onrender.com). In dev, Vite's
// proxy (vite.config.js) forwards /api to the local Flask server.
const API_BASE = import.meta.env.VITE_API_URL || '/api'
const api = axios.create({ baseURL: API_BASE })

export default function App() {
  const [caseId, setCaseId] = useState(null)
  const [caseMeta, setCaseMeta] = useState(null)
  const [graphData, setGraphData] = useState(null)
  const [centrality, setCentrality] = useState([])
  const [communities, setCommunities] = useState([])
  const [anomalies, setAnomalies] = useState([])
  const [linkPredictions, setLinkPredictions] = useState([])
  const [pathResult, setPathResult] = useState(null)
  const [log, setLog] = useState([])
  const [timeline, setTimeline] = useState([])
  const [selectedNode, setSelectedNode] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const fileInputRef = useRef()

  const anomalyMap = React.useMemo(() => {
    const m = {}
    anomalies.forEach(a => { m[a.entity_id] = a.anomaly_score })
    return m
  }, [anomalies])

  const loadAllAnalysis = useCallback(async (id) => {
    const [g, c, comm, anom, links, logRes] = await Promise.all([
      api.get(`/cases/${id}/graph`),
      api.get(`/cases/${id}/centrality`),
      api.get(`/cases/${id}/communities`),
      api.get(`/cases/${id}/anomalies`),
      api.get(`/cases/${id}/link-predictions`),
      api.get(`/cases/${id}/log`),
    ])
    setGraphData(g.data)
    setCentrality(c.data)
    setCommunities(comm.data)
    setAnomalies(anom.data)
    setLinkPredictions(links.data)
    setLog(logRes.data)
  }, [])

  const handleLoadDemo = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.post('/cases/load-demo')
      const id = res.data.case_id
      setCaseId(id)
      const casesRes = await api.get('/cases')
      setCaseMeta(casesRes.data.find(c => c.case_id === id))
      await loadAllAnalysis(id)
    } catch (e) {
      setError(e.response?.data?.error || 'Failed to load demo case. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  const handleFileUpload = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      let json
      try {
        const text = await file.text()
        json = JSON.parse(text)
      } catch (parseErr) {
        throw new Error('That file isn\'t valid JSON.')
      }
      const res = await api.post('/cases/upload', json)
      const id = res.data.case_id
      setCaseId(id)
      const casesRes = await api.get('/cases')
      setCaseMeta(casesRes.data.find(c => c.case_id === id))
      await loadAllAnalysis(id)
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Could not process this file.')
    } finally {
      setLoading(false)
      e.target.value = ''
    }
  }

  const handleRunPath = async (source, target) => {
    try {
      const res = await api.get(`/cases/${caseId}/path`, { params: { source, target } })
      setPathResult(res.data)
    } catch (e) {
      setPathResult({ error: e.response?.data?.error || 'Path lookup failed.' })
    }
    try {
      const logRes = await api.get(`/cases/${caseId}/log`)
      setLog(logRes.data)
    } catch (e) { /* non-fatal */ }
  }

  const handleLoadTimeline = async (entityId) => {
    try {
      const res = await api.get(`/cases/${caseId}/timeline`, {
        params: entityId ? { entity_id: entityId } : {},
      })
      setTimeline(res.data)
    } catch (e) {
      setTimeline([])
    }
  }

  const handleNodeClick = (node) => {
    setSelectedNode(node)
  }

  return (
    <div className="app-shell">
      <div className="rail">
        <div className="masthead">
          <h1>Forensic Criminal Analyzer</h1>
          <div className="case-note">
            Entity-relationship analysis over digital device artifacts. Investigative aid — surfaces patterns for analyst review, not automated determinations.
          </div>
        </div>

        <div>
          <div className="section-label">Case</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <button className="btn btn-primary" onClick={handleLoadDemo} disabled={loading}>
              {loading ? 'Loading…' : 'Load synthetic demo case'}
            </button>
            <div className="file-drop" onClick={() => fileInputRef.current.click()}>
              Upload forensic export (.json)
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept="application/json"
              style={{ display: 'none' }}
              onChange={handleFileUpload}
            />
          </div>
          {error && <div style={{ color: 'var(--danger)', fontSize: 12, marginTop: 8 }}>{error}</div>}
        </div>

        {caseMeta && (
          <div>
            <div className="section-label">Case summary</div>
            <div className="case-meta-row"><span className="k">Case ID</span><span className="v">{caseMeta.case_id}</span></div>
            <div className="case-meta-row"><span className="k">Entities</span><span className="v">{caseMeta.entity_count}</span></div>
            <div className="case-meta-row"><span className="k">Artifacts</span><span className="v">{caseMeta.artifact_count}</span></div>
            <div className="case-meta-row"><span className="k">Loaded</span><span className="v">{new Date(caseMeta.loaded_at).toLocaleTimeString()}</span></div>
            <div style={{ marginTop: 10 }}>
              <ExportMenu apiBase={API_BASE} caseId={caseId} />
            </div>
          </div>
        )}

        {selectedNode && (
          <div>
            <div className="section-label">Selected entity</div>
            <div className="case-meta-row"><span className="k">Name</span><span className="v">{selectedNode.name}</span></div>
            <div className="case-meta-row"><span className="k">Phone</span><span className="v">{selectedNode.phone}</span></div>
            <div className="case-meta-row"><span className="k">Device</span><span className="v">{selectedNode.device_id}</span></div>
          </div>
        )}
      </div>

      <div className="stage">
        {caseId && (
          <div className="stage-header">
            <div className="eyebrow">Entity network</div>
            <h2>{caseMeta?.case_id}</h2>
          </div>
        )}
        <GraphView
          graphData={graphData}
          anomalyMap={anomalyMap}
          highlightPath={pathResult && !pathResult.error ? pathResult.path : []}
          onNodeClick={handleNodeClick}
          selectedNodeId={selectedNode?.id}
        />
        {caseId && (
          <div className="legend">
            <span><span className="dot" style={{ background: '#58A6FF' }}></span>call</span>
            <span><span className="dot" style={{ background: '#3FB950' }}></span>chat</span>
            <span><span className="dot" style={{ background: '#E3B341' }}></span>file transfer</span>
            <span><span className="dot" style={{ background: '#BC8CFF' }}></span>co-location</span>
            <span><span className="dot" style={{ background: '#F85149' }}></span>high anomaly</span>
          </div>
        )}
      </div>

      <AnalysisPanel
        caseId={caseId}
        entities={graphData?.nodes || []}
        centrality={centrality}
        communities={communities}
        anomalies={anomalies}
        linkPredictions={linkPredictions}
        pathResult={pathResult}
        onRunPath={handleRunPath}
        log={log}
        timeline={timeline}
        onLoadTimeline={handleLoadTimeline}
        onSelectEntity={(id) => {
          const node = graphData?.nodes.find(n => n.id === id)
          if (node) setSelectedNode(node)
        }}
      />
    </div>
  )
}
