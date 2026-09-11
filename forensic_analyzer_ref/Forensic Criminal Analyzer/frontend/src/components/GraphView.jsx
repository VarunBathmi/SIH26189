import React, { useRef, useEffect, useMemo } from 'react'
import ForceGraph2D from 'react-force-graph-2d'

const KIND_COLORS = {
  call: '#58A6FF',
  chat: '#3FB950',
  file_transfer: '#E3B341',
  colocation: '#BC8CFF',
}

export default function GraphView({ graphData, anomalyMap, highlightPath, onNodeClick, selectedNodeId }) {
  const fgRef = useRef()

  const data = useMemo(() => {
    if (!graphData) return { nodes: [], links: [] }
    return {
      nodes: graphData.nodes.map(n => ({ ...n })),
      links: graphData.edges.map(e => ({
        source: e.source,
        target: e.target,
        weight: e.weight,
        kinds: e.kinds,
      })),
    }
  }, [graphData])

  useEffect(() => {
    if (fgRef.current) {
      fgRef.current.d3Force('charge').strength(-140)
    }
  }, [data])

  const pathSet = useMemo(() => new Set(highlightPath || []), [highlightPath])

  if (!graphData) {
    return (
      <div className="empty-state" style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        No case loaded. Load the demo case or upload a forensic export from the left rail.
      </div>
    )
  }

  return (
    <ForceGraph2D
      ref={fgRef}
      graphData={data}
      backgroundColor="rgba(0,0,0,0)"
      nodeLabel={n => `${n.name}\n${n.device_id || ''}`}
      linkColor={l => {
        const dominant = Object.entries(l.kinds || {}).sort((a, b) => b[1] - a[1])[0]
        return dominant ? (KIND_COLORS[dominant[0]] || '#4A5568') : '#4A5568'
      }}
      linkWidth={l => Math.min(1 + Math.log2((l.weight || 1) + 1), 5)}
      linkDirectionalParticles={l => {
        const a = pathSet.has(l.source.id || l.source)
        const b = pathSet.has(l.target.id || l.target)
        return a && b ? 3 : 0
      }}
      linkDirectionalParticleWidth={3}
      linkDirectionalParticleColor={() => '#E3B341'}
      nodeCanvasObject={(node, ctx, globalScale) => {
        const isSelected = node.id === selectedNodeId
        const isOnPath = pathSet.has(node.id)
        const score = anomalyMap ? anomalyMap[node.id] : undefined
        const baseColor = score !== undefined
          ? blendColor(score)
          : '#58A6FF'

        const radius = isSelected ? 8 : 6
        ctx.beginPath()
        ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI)
        ctx.fillStyle = isOnPath ? '#E3B341' : baseColor
        ctx.fill()
        if (isSelected) {
          ctx.lineWidth = 2
          ctx.strokeStyle = '#E6EDF3'
          ctx.stroke()
        }

        const label = node.name
        const fontSize = Math.max(11 / globalScale, 3)
        ctx.font = `${fontSize}px Inter, sans-serif`
        ctx.fillStyle = 'rgba(230,237,243,0.85)'
        ctx.textAlign = 'center'
        ctx.fillText(label, node.x, node.y + radius + fontSize)
      }}
      onNodeClick={(node) => onNodeClick && onNodeClick(node)}
    />
  )
}

function blendColor(score) {
  // 0 = calm cyan, 1 = danger red
  const r = Math.round(88 + (248 - 88) * score)
  const g = Math.round(166 + (81 - 166) * score)
  const b = Math.round(255 + (73 - 255) * score)
  return `rgb(${r},${g},${b})`
}
