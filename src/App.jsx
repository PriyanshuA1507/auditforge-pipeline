import { useState } from 'react'
import './index.css'
import JsonOutput from './components/JsonOutput.jsx'
import ScanResults from './components/ScanResults.jsx'
import Dashboard from './components/Dashboard.jsx'
import ScanPanel from './components/ScanPanel.jsx'
import { SectionCard, CheckRow, MetaItem, PipeStep, ScanItem } from './components/UI.jsx'
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js'

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement)

export default function App() {
  // UI state
  const [running,    setRunning]    = useState(false)

  // Step visibility
  const [showMeta,   setShowMeta]   = useState(false)
  const [showVal,    setShowVal]    = useState(false)
  const [showHash,   setShowHash]   = useState(false)
  const [showScan,   setShowScan]   = useState(false)
  const [showPipe,   setShowPipe]   = useState(false)
  const [showJson,   setShowJson]   = useState(false)
  const [showDash,   setShowDash]   = useState(false)

  // Data
  const [meta,       setMeta]       = useState([])
  const [valChecks,  setValChecks]  = useState([])
  const [valPassed,  setValPassed]  = useState(false)
  const [hashValue,  setHashValue]  = useState('')
  const [hashVerify, setHashVerify] = useState(false)
  const [scanItems,  setScanItems]  = useState([])
  const [pipeStates, setPipeStates] = useState({ s1:'idle', s2:'idle', s3:'idle', s4:'idle' })
  const [pipeProgress, setPipeProgress] = useState(0)
  const [pipeMsg,    setPipeMsg]    = useState('')
  const [jsonData,   setJsonData]   = useState(null)
  const [fileName,   setFileName]   = useState('')

  function resetAll() {
    setShowMeta(false); setShowVal(false); setShowHash(false)
    setShowScan(false); setShowPipe(false); setShowJson(false); setShowDash(false)
    setMeta([]); setValChecks([]); setValPassed(false)
    setHashValue(''); setHashVerify(false); setScanItems([])
    setPipeStates({ s1:'idle', s2:'idle', s3:'idle', s4:'idle' })
    setPipeProgress(0); setPipeMsg(''); setJsonData(null)
  }

  function downloadJSON() {
    if (!jsonData) return
    const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = (jsonData.report_id || 'scan-report') + '.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  function downloadCSV() {
    if (!jsonData) return
    // If VT engine results exist, export engines as CSV rows
    const lines = []
    if (jsonData.vt_analysis) {
      lines.push(['engine_name','engine_version','method','result','engine_update'].join(','))
      Object.keys(jsonData.vt_analysis).forEach(k => {
        const r = jsonData.vt_analysis[k]
        const name = (r.engine_name || k).replace(/,/g, ' ')
        const ver = (r.engine_version || '').toString().replace(/,/g, ' ')
        const method = (r.method || '').toString().replace(/,/g, ' ')
        const result = (r.result || r.category || '').toString().replace(/,/g, ' ')
        const upd = (r.engine_update || '').toString()
        lines.push([name, ver, method, result, upd].join(','))
      })
    } else {
      // Fallback: export top-level keys
      lines.push(['key','value'].join(','))
      Object.keys(jsonData).forEach(k => lines.push([k, String(jsonData[k]).replace(/,/g,' ')]))
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = (jsonData.report_id || 'scan-report') + '.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="app">
      {/* Header */}
      <header className="app-header">
        <i className="ti ti-shield-lock logo-icon" aria-hidden="true" />
        <div>
          <h1>AuditForge</h1>
        </div>
        <p>Cybersecurity Audit Report Parser — Priyanshu</p>
      </header>

      <div className="app-body">

        <ScanPanel
          setShowMeta={setShowMeta} setMeta={setMeta}
          setShowVal={setShowVal} setValChecks={setValChecks} setValPassed={setValPassed}
          setShowHash={setShowHash} setHashValue={setHashValue} setHashVerify={setHashVerify}
          setShowScan={setShowScan} setScanItems={setScanItems}
          setShowPipe={setShowPipe} setPipeStates={setPipeStates} setPipeProgress={setPipeProgress} setPipeMsg={setPipeMsg}
          setShowJson={setShowJson} setJsonData={setJsonData}
          setShowDash={setShowDash} setFileName={setFileName}
          setRunning={setRunning}
        />

        {/* STEP 1 — Metadata */}
        <SectionCard show={showMeta} title="Step 1 — file metadata extracted" icon="ti-file-description">
          <div className="meta-grid">
            {meta.map(m => <MetaItem key={m.label} label={m.label} value={m.value} />)}
          </div>
        </SectionCard>

        {/* STEP 2 — Validation */}
        <SectionCard show={showVal} title="Step 2 — file validation" icon="ti-file-check">
          {valChecks.map(c => (
            <CheckRow key={c.label} pass={c.pass} label={c.label} detail={c.detail} />
          ))}
          {!valPassed && (
            <div style={{ marginTop: 10, padding: '10px 14px', borderRadius: 'var(--r)', background: 'rgba(226,75,74,.1)', border: '1px solid rgba(226,75,74,.3)', color: 'var(--err)', fontSize: 13 }}>
              <i className="ti ti-alert-circle" aria-hidden="true" /> &nbsp;
              Validation failed — pipeline stopped. Only PDF or DOCX files under 50 MB are accepted.
            </div>
          )}
        </SectionCard>

        {/* STEP 3 — Hashing */}
        <SectionCard show={showHash} title="Step 3 — SHA-256 hashing & verification" icon="ti-fingerprint">
          <CheckRow pass={!!hashValue} label="SHA-256 hash computed (Web Crypto API)" detail={hashValue ? 'Hash generated — 64 character hex string' : 'Computing…'} />
          {hashVerify !== null && hashValue && (
            <CheckRow pass={hashVerify} label="Hash verification — re-computed and compared" detail={hashVerify ? 'Both hashes match — file integrity confirmed' : 'Hash mismatch — file may be corrupted'} />
          )}
          {hashValue && (
            <>
              <div style={{ fontSize: 11, color: 'var(--text2)', fontWeight: 700, letterSpacing: '.05em', marginTop: 12, marginBottom: 4 }}>FULL SHA-256 HASH</div>
              <div className="hash-box">{hashValue}</div>
            </>
          )}
        </SectionCard>

        {/* STEP 4 — Malware scan */}
        <SectionCard show={showScan} title="Step 4 — malware scan" icon="ti-virus-search">
          {scanItems.map(s => (
            <ScanItem key={s.label} icon={s.icon} label={s.label} value={s.value} ok={s.ok} />
          ))}
          {jsonData && jsonData.vt_analysis && (
            <div style={{ marginTop: 10 }}>
              <ScanResults data={jsonData.vt_analysis} meta={jsonData.vt_meta} />
            </div>
          )}
        </SectionCard>

        {/* STEP 5 — Pipeline */}
        <SectionCard show={showPipe} title="Step 5 — pipeline processing" icon="ti-player-play">
          <div className="pipe-steps">
            <PipeStep id="pp1" label="Ingestion" icon="ti-download" state={pipeStates.s1} />
            <PipeStep id="pp2" label="Parsing" icon="ti-cpu" state={pipeStates.s2} />
            <PipeStep id="pp3" label="NLP extract" icon="ti-brain" state={pipeStates.s3} />
            <PipeStep id="pp4" label="Schema build" icon="ti-check" state={pipeStates.s4} />
          </div>
          <div className="progress-wrap"><div className="progress-bar" style={{ width: `${pipeProgress}%` }} /></div>
          <div className="pipe-status">{pipeMsg}</div>
        </SectionCard>

        {/* STEP 6 — JSON output */}
        <SectionCard show={showJson} title="Step 6 — extracted metadata (JSON output)" icon="ti-braces">
          {jsonData && (
            <>
              <div className="export-bar">
                <button className="btn small" onClick={downloadJSON}>Export JSON</button>
                <button className="btn small" onClick={downloadCSV}>Export CSV</button>
              </div>
              <JsonOutput data={jsonData} />
            </>
          )}
        </SectionCard>

        {/* Dashboard */}
        {showDash && <Dashboard fileName={fileName} data={jsonData} />}

      </div>
    </div>
  )
}
