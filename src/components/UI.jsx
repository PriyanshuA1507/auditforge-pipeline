import React from 'react'

export function SectionCard({ show, title, icon, children }) {
  if (!show) return null
  return (
    <div className="card fade-in">
      <div className="sec-title">
        <i className={`ti ${icon}`} aria-hidden="true" />
        {title}
      </div>
      {children}
    </div>
  )
}

export function CheckRow({ pass, label, detail }) {
  return (
    <div className={`check-row ${pass ? 'pass' : 'fail'}`}>
      <i
        className={`ti ${pass ? 'ti-circle-check' : 'ti-circle-x'} ci`}
        style={{ color: pass ? 'var(--ok)' : 'var(--err)' }}
        aria-hidden="true"
      />
      <span className="cl">{label}</span>
      <span className="cv">{detail}</span>
    </div>
  )
}

export function MetaItem({ label, value }) {
  return (
    <div className="meta-item">
      <div className="lbl">{label}</div>
      <div className="val">{value}</div>
    </div>
  )
}

export function PipeStep({ id, label, icon, state }) {
  return (
    <div className={`pipe-step ${state}`} id={id}>
      <i className={`ti ${icon} pi`} aria-hidden="true" />
      <span className="pl">{label}</span>
      <span className="pb">
        {state === 'idle' ? 'Idle' : state === 'running' ? 'Running…' : 'Done'}
      </span>
    </div>
  )
}

export function ScanItem({ icon, label, value, ok }) {
  return (
    <div className="scan-item">
      <i
        className={`ti ${icon} si`}
        style={{ color: ok ? 'var(--ok)' : 'var(--err)' }}
        aria-hidden="true"
      />
      <span className="sl">{label}</span>
      <span className="sv" style={{ color: ok ? 'var(--ok)' : 'var(--err)' }}>
        {value}
      </span>
    </div>
  )
}

export default null
