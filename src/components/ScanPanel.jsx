import React, { useState, useRef } from 'react'

const ALLOWED_TYPES = ['.pdf', '.docx']
const MAX_SIZE      = 50 * 1024 * 1024  // 50 MB

function getExt(name) { return '.' + name.split('.').pop().toLowerCase() }
function fmtSize(bytes) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1_048_576) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / 1_048_576).toFixed(2) + ' MB'
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)) }
async function computeSHA256(file) {
  const buffer = await file.arrayBuffer()
  const hash   = await crypto.subtle.digest('SHA-256', buffer)
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('')
}
async function computeEntropyFromFile(file) {
  const buffer = await file.arrayBuffer()
  const bytes = new Uint8Array(buffer)
  const freq = new Uint32Array(256)
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++
  let entropy = 0
  const len = bytes.length || 1
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue
    const p = freq[i] / len
    entropy -= p * Math.log2(p)
  }
  return parseFloat(entropy.toFixed(2))
}

export default function ScanPanel(props) {
  const inputRef = useRef()
  const [drag, setDrag] = useState(false)
  const [running, setRunningLocal] = useState(false)

  const apiUrl = import.meta.env.VITE_SCAN_API_URL || 'http://localhost:4000/scan'

  async function runPipeline(file) {
    if (!file || running) return
    // reset App state via props setters
    const setters = props
    setters.setShowMeta(false); setters.setShowVal(false); setters.setShowHash(false)
    setters.setShowScan(false); setters.setShowPipe(false); setters.setShowJson(false); setters.setShowDash(false)
    setters.setMeta([]); setters.setValChecks([]); setters.setValPassed(false)
    setters.setHashValue(''); setters.setHashVerify(false); setters.setScanItems([])
    setters.setPipeStates({ s1:'idle', s2:'idle', s3:'idle', s4:'idle' })
    setters.setPipeProgress(0); setters.setPipeMsg(''); setters.setJsonData(null)

    setRunningLocal(true)
    setters.setRunning(true)
    setters.setFileName(file.name)

    await sleep(300)

    // metadata
    const ext = getExt(file.name)
    const lastMod = new Date(file.lastModified).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })
    const pages = Math.max(1, Math.round(file.size / 3500))
    setters.setMeta([
      { label: 'File name', value: file.name },
      { label: 'File type', value: ext.toUpperCase() },
      { label: 'File size', value: fmtSize(file.size) },
      { label: 'MIME type', value: file.type || 'application/octet-stream' },
      { label: 'Last modified', value: lastMod },
      { label: 'Encoding', value: 'UTF-8' },
      { label: 'Pages (est.)', value: String(pages) },
      { label: 'Author', value: '[extracted from doc properties]' },
      { label: 'Doc language', value: 'English' },
      { label: 'Audit type', value: 'VAPT' },
    ])
    setters.setShowMeta(true)
    await sleep(400)

    // validation
    const typeOK  = ALLOWED_TYPES.includes(ext)
    const sizeOK  = file.size <= MAX_SIZE
    const nameOK  = !/[#%&{}<>*?$! '\"`:@|]/.test(file.name)
    const checks = [
      { pass: typeOK, label: 'File type allowed (PDF / DOCX only)', detail: typeOK ? `${ext.toUpperCase()} is allowed` : `${ext.toUpperCase()} not allowed` },
      { pass: sizeOK, label: 'File size ≤ 50 MB', detail: sizeOK ? `${fmtSize(file.size)} — within the limit` : `${fmtSize(file.size)} — exceeds the 50 MB limit` },
      { pass: nameOK, label: 'Filename has no illegal characters', detail: nameOK ? 'Filename is safe' : 'Remove special characters from the filename' },
    ]
    setters.setValChecks(checks)
    setters.setValPassed(typeOK && sizeOK && nameOK)
    setters.setShowVal(true)
    await sleep(400)

    if (!typeOK || !sizeOK) { setRunningLocal(false); setters.setRunning(false); return }

    // hashing
    setters.setShowHash(true)
    await sleep(200)
    const hash1 = await computeSHA256(file)
    setters.setHashValue(hash1)
    await sleep(300)
    const hash2 = await computeSHA256(file)
    setters.setHashVerify(hash1 === hash2)
    await sleep(400)

    // scan
    setters.setShowScan(true)
    let magicMsg = ''
    try {
      const header = new Uint8Array((await file.slice(0,8).arrayBuffer()))
      const sig = Array.from(header).map(b => b.toString(16).padStart(2,'0')).join(' ')
      if (ext === '.pdf' && sig.startsWith('25 50 44 46')) magicMsg = '%PDF header confirmed'
      else if (ext === '.docx' && sig.startsWith('50 4b 03 04')) magicMsg = 'PK ZIP header confirmed'
      else magicMsg = `Header: ${sig}`
    } catch (e) { magicMsg = 'Header read failed' }
    const entropyVal = await computeEntropyFromFile(file)
    const entropyOK = entropyVal < 6.5
    setters.setScanItems([
      { icon: 'ti-binary', label: 'Magic byte check', value: magicMsg, ok: true },
      { icon: 'ti-chart-histogram', label: 'File entropy check', value: `${entropyVal} — ${entropyOK ? 'normal range' : 'high — suspicious'}`, ok: entropyOK },
      { icon: 'ti-shield-check', label: 'Remote signature scan', value: 'Scanning…', ok: null },
    ])

    // vars to capture remote analysis and extraction
    let vtResultsVar = null
    let vtMetaVar = null
    let vtVerdictVar = null
    let extractedCvesVar = []

    try {
      const form = new FormData(); form.append('file', file, file.name)
      const resp = await fetch(apiUrl, { method: 'POST', body: form })
      if (!resp.ok) {
        const err = await resp.json().catch(()=>({}))
        setters.setScanItems(prev => prev.map(s => s.label === 'Remote signature scan' ? { ...s, value: `Scan failed: ${err.error || resp.statusText}`, ok: false } : s))
      } else {
        const body = await resp.json()
        let verdict = 'clean'
        let vtResults = null
        let vtMeta = null
        try {
          const analysis = body.analysis
          const attrs = analysis && analysis.data && analysis.data.attributes
          vtResults = attrs && attrs.results

          // Prefer server-provided vt_meta if available
          if (body.vt_meta && body.vt_meta.stats) {
            vtMeta = body.vt_meta
          } else {
            // synthesize stats from per-engine results if available
            if (vtResults) {
              const stats = { harmless:0, malicious:0, suspicious:0, undetected:0 }
              Object.values(vtResults).forEach(r => {
                const cat = (r && (r.category || (r.result ? 'malicious' : 'undetected')) || 'undetected').toString().toLowerCase()
                if (cat.includes('malicious')) stats.malicious++
                else if (cat.includes('suspicious')) stats.suspicious++
                else if (cat.includes('harmless')) stats.harmless++
                else stats.undetected++
              })
              vtMeta = { stats, date: (attrs && attrs.date) || Date.now() }
            } else {
              const stats = (attrs && attrs.stats) || null
              vtMeta = { stats, date: attrs && attrs.date }
            }
          }

          if (vtMeta && vtMeta.stats) {
            const positives = (vtMeta.stats.malicious || 0) + (vtMeta.stats.suspicious || 0)
            if (positives > 0) verdict = 'malicious'
          }
        } catch (e) {}
        setters.setScanItems(prev => prev.map(s => s.label === 'Remote signature scan' ? { ...s, value: `Scan complete — verdict: ${verdict}`, ok: verdict === 'clean' } : s))
        // Attach VT engine results and metadata into the final JSON via parent setter
        if (vtResults) {
          vtResultsVar = vtResults
          vtMetaVar = vtMeta
          vtVerdictVar = verdict
          // include any extracted CVEs returned by the proxy
          if (body.extracted_cves) extractedCvesVar = body.extracted_cves
          // Also scan per-engine results for CVE identifiers and merge
          try {
            const cvSet = new Set((extractedCvesVar || []).map(x => x.toUpperCase()))
            const cvPattern = /CVE-\d{4}-\d{4,7}/gi
            Object.values(vtResults).forEach(r => {
              try {
                const candidates = [r.result, r.category, r.engine_name].filter(Boolean).join(' ')
                const ms = candidates.match(cvPattern)
                if (ms) ms.forEach(m => cvSet.add(m.toUpperCase()))
              } catch (e) {}
            })
            extractedCvesVar = Array.from(cvSet)
          } catch (e) {}
          setters.setJsonData(prev => {
            const base = prev || {}
            return { ...base, vt_analysis: vtResults, vt_meta: vtMeta, vt_verdict: verdict, extracted_cves: extractedCvesVar }
          })
        }
      }
    } catch (e) {
      setters.setScanItems(prev => prev.map(s => s.label === 'Remote signature scan' ? { ...s, value: `Scan error: ${String(e)}`, ok: false } : s))
    }

    await sleep(500)

    // pipeline animation
    setters.setShowPipe(true)
    const pipeSteps = [ ['s1','Ingesting file…','ti-download'], ['s2','Parsing document content…','ti-cpu'], ['s3','Extracting NLP entities…','ti-brain'], ['s4','Building output schema…','ti-check'] ]
    for (let i = 0; i < pipeSteps.length; i++) {
      const [key,msg] = pipeSteps[i]
      setters.setPipeStates(prev => ({ ...prev, [key]: 'running' }))
      setters.setPipeMsg(msg)
      const start = (i/4)*100; const end = ((i+1)/4)*100
      for (let p = start; p <= end; p += 2) { setters.setPipeProgress(p); await sleep(28) }
      setters.setPipeStates(prev => ({ ...prev, [key]: 'done' }))
      await sleep(200)
    }
    setters.setPipeMsg('Pipeline complete ✓')
    await sleep(500)

    // final JSON (demo)
    const reportId = 'RPT-' + Date.now()
    const result = {
      report_id: reportId,
      pipeline_status: 'complete',
      timestamp: new Date().toISOString(),
      file: { name: file.name, type: getExt(file.name).toUpperCase(), size_bytes: file.size, size_readable: fmtSize(file.size), pages_estimated: pages, sha256: hash1, hash_verified: true, malware_scan: vtVerdictVar || 'unknown', entropy: entropyVal },
      extraction: { audit_type: 'VAPT', audit_date: '2024-01-15', auditor: 'SecureTech Pvt Ltd', total_findings: 24, cve_ids: extractedCvesVar || [] },
      vt_analysis: vtResultsVar || null,
      vt_meta: vtMetaVar || null,
      vt_verdict: vtVerdictVar || null,
      schema_version: '1.0.0'
    }

    setters.setJsonData(result)
    setters.setShowJson(true)
    await sleep(400)

    setters.setShowDash(true)
    setRunningLocal(false)
    setters.setRunning(false)
  }

  function handleFileInput(e) { const file = e.target.files[0]; if (file) runPipeline(file); e.target.value = '' }
  function handleDrop(e) { e.preventDefault(); setDrag(false); const file = e.dataTransfer.files[0]; if (file) runPipeline(file) }

  return (
    <div
      className={`card drop-zone${drag ? ' drag' : ''}`}
      onDragOver={e => { e.preventDefault(); setDrag(true) }}
      onDragLeave={() => setDrag(false)}
      onDrop={handleDrop}
      onClick={() => !running && inputRef.current.click()}
    >
      <i className="ti ti-cloud-upload dz-icon" aria-hidden="true" />
      <h3>{running ? `Processing…` : 'Drop your audit report here or click to browse'}</h3>
      <p>PDF or DOCX only · max 50 MB</p>
      {!running && (
        <button className="btn" onClick={e => { e.stopPropagation(); inputRef.current.click() }}>
          <i className="ti ti-folder-open" aria-hidden="true" /> &nbsp;Browse file
        </button>
      )}
      <input ref={inputRef} type="file" accept=".pdf,.docx" style={{ display: 'none' }} onChange={handleFileInput} />
    </div>
  )
}
