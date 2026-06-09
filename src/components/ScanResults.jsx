import React, { useState } from 'react'

function fmtDate(ts) {
  if (!ts) return ''
  // VT often returns seconds timestamp
  const n = Number(ts)
  if (Number.isFinite(n) && n > 1e10) return new Date(n).toLocaleString()
  if (Number.isFinite(n)) return new Date(n * 1000).toLocaleString()
  return String(ts)
}

export default function ScanResults({ data, meta }) {
  const [collapsed, setCollapsed] = useState(false)
  if (!data) return null
  const engines = Object.keys(data)
  const stats = meta && meta.stats
  const date = meta && meta.date
  return (
    <div className="vt-results">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <div style={{ fontSize: 13, color: 'var(--text2)' }}>{engines.length} engines</div>
        <div>
          <button className="btn small" onClick={() => setCollapsed(c => !c)} style={{ marginRight: 8 }}>{collapsed ? 'Expand' : 'Collapse'}</button>
        </div>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h4 style={{ margin: 0 }}>VirusTotal engine results</h4>
        <div style={{ fontSize: 12, color: 'var(--text2)' }}>{date ? fmtDate(date) : ''}</div>
      </div>
      {stats && (
        <div style={{ display: 'flex', gap: 12, marginTop: 8, marginBottom: 8, fontSize: 13 }}>
          <div>Harmless: <strong>{stats.harmless ?? 0}</strong></div>
          <div>Malicious: <strong>{stats.malicious ?? 0}</strong></div>
          <div>Suspicious: <strong>{stats.suspicious ?? 0}</strong></div>
          <div>Undetected: <strong>{stats.undetected ?? 0}</strong></div>
        </div>
      )}
      <div className={`vt-list ${collapsed ? 'collapsed' : ''}`}>
        {engines.map(k => {
          const r = data[k]
          const verdict = r.result || r.category || 'clean'
          const ok = verdict === 'clean' || verdict === 'undetected' || verdict === null
          return (
            <div key={k} className={`vt-row ${ok ? 'ok' : 'bad'}`} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderBottom: '1px solid rgba(0,0,0,0.04)' }}>
              <div style={{ minWidth: 160 }}>
                <div style={{ fontWeight: 700 }}>{r.engine_name || k}</div>
                <div style={{ fontSize: 12, color: 'var(--text2)' }}>{r.engine_version ? `v${r.engine_version}` : ''}</div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontWeight: 800, color: ok ? 'var(--ok)' : 'var(--err)' }}>{verdict}</div>
                <div style={{ fontSize: 12, color: 'var(--text2)' }}>{r.method || ''}{r.engine_update ? ` · updated ${fmtDate(r.engine_update)}` : ''}</div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
