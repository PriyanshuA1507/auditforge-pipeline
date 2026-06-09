import React from 'react'
import { Doughnut, Bar } from 'react-chartjs-2'

const DUMMY_CVES = [
  { id: 'CVE-2024-1234', score: 9.1, sev: 'Critical' },
  { id: 'CVE-2024-5678', score: 8.9, sev: 'Critical' },
  { id: 'CVE-2023-9876', score: 8.2, sev: 'Critical' },
]

const DUMMY_ASSETS = [
  '192.168.1.10', '10.0.1.50', '172.16.5.100',
  'api.target.com', 'admin.target.com',
  'Apache 2.4.51', 'OpenSSL 1.0.2', 'nginx 1.18.0',
]

export default function Dashboard({ fileName, data }) {
  const vt_stats = data && data.vt_meta && data.vt_meta.stats
  const vt_analysis = data && data.vt_analysis
  const extraction = data && data.extraction

  const critical = (vt_stats && (vt_stats.malicious || 0)) || (extraction && extraction.critical_count) || 0
  const high = (vt_stats && (vt_stats.suspicious || 0)) || (extraction && extraction.high_count) || 0
  const harmless = (vt_stats && (vt_stats.harmless || 0)) || 0
  const undetected = (vt_stats && (vt_stats.undetected || 0)) || 0
  const totalFindings = extraction && extraction.total_findings ? extraction.total_findings : (critical + high)
  const assets = (extraction && extraction.assets) || (data && data.assets) || []
  const malwareStatus = (data && data.file && data.file.malware_scan) || (data && data.vt_verdict) || 'Unknown'

  const sevData = {
    labels: ['Malicious', 'Suspicious', 'Harmless', 'Undetected'],
    datasets: [{
      data: [critical, high, harmless, undetected],
      backgroundColor: ['#e24b4a', '#f59e0b', '#3b82f6', '#22c55e'],
      borderWidth: 0,
    }],
  }

  // CVSS distribution – try to use extraction.cvss_buckets else synthesize a small distribution
  const cvssBuckets = (extraction && extraction.cvss_buckets) || [0,0,0,0,0]
  const cvssData = {
    labels: ['5.0–6.0', '6.0–7.0', '7.0–8.0', '8.0–9.0', '9.0–10'],
    datasets: [{
      label: 'Findings',
      data: cvssBuckets,
      backgroundColor: '#3b82f6',
      borderRadius: 4,
      borderWidth: 0,
    }],
  }

  const chartOpts = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#6b82a8' }, grid: { display: false } },
      y: { ticks: { color: '#6b82a8' }, grid: { color: '#1e2d44' } },
    },
  }

  const donutOpts = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
  }

  const cves = (extraction && extraction.cve_ids && extraction.cve_ids.length) ? extraction.cve_ids.map(id => ({ id, score: '-', sev: 'Unknown' })) : []

  return (
    <div className="card fade-in">
      <div className="sec-title">
        <i className="ti ti-layout-dashboard" aria-hidden="true" />
        Cybersecurity audit analytics dashboard
      </div>

      <div className="dash-stats">
        {[
          { lbl: 'Total findings', val: String(totalFindings || 0),  color: 'var(--text)'   },
          { lbl: 'Critical CVEs',  val: String(critical || 0),   color: 'var(--err)'    },
          { lbl: 'High severity',  val: String(high || 0),   color: 'var(--warn)'   },
          { lbl: 'Assets affected',val: String((assets && assets.length) || 0),   color: 'var(--accent)' },
          { lbl: 'Malware status', val: String(malwareStatus),color: malwareStatus === 'clean' ? 'var(--ok)' : 'var(--err)'    },
        ].map(s => (
          <div className="dash-stat" key={s.lbl}>
            <div className="ds-lbl">{s.lbl}</div>
            <div className="ds-val" style={{ color: s.color }}>{s.val}</div>
          </div>
        ))}
      </div>

      <div className="dash-two">
        <div>
          <div className="sec-title" style={{ marginBottom: 10 }}>Top CVE findings</div>
          {cves.length > 0 ? (
            <table className="cve-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>CVSS</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {cves.map(c => (
                  <tr key={c.id}>
                    <td style={{ fontFamily: 'var(--fm)', fontSize: 11 }}>{c.id}</td>
                    <td style={{ fontFamily: 'var(--fm)' }}>{c.score}</td>
                    <td>
                      <span className={`sev-badge sev-${(c.sev || 'unknown').toLowerCase()}`}>
                        {c.sev}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{ color: 'var(--text2)', padding: '8px 10px', background: 'var(--bg3)', border: '1px solid var(--border)', borderRadius: 8 }}>No CVE findings were extracted from this report.</div>
          )}
        </div>

        <div>
          <div className="sec-title" style={{ marginBottom: 10 }}>Severity breakdown</div>
          <div style={{ position: 'relative', height: 200 }}>
            <Doughnut
              data={sevData}
              options={donutOpts}
              aria-label="Severity breakdown"
            />
          </div>
          <div className="chart-legend">
            {[['#e24b4a',`Malicious ${critical}`],['#f59e0b',`Suspicious ${high}`],['#3b82f6',`Harmless ${harmless}`],['#22c55e',`Undetected ${undetected}`]].map(([col, lbl]) => (
              <span key={lbl}>
                <span className="dot" style={{ background: col }} />
                {lbl}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div style={{ marginBottom: 18 }}>
        <div className="sec-title" style={{ marginBottom: 10 }}>CVSS score distribution</div>
        <div style={{ position: 'relative', height: 180 }}>
          <Bar
            data={cvssData}
            options={chartOpts}
            aria-label="CVSS score distribution bar chart"
          />
        </div>
      </div>

      <div>
        <div className="sec-title" style={{ marginBottom: 10 }}>Affected assets</div>
        <div className="asset-wrap">
          {(assets && assets.length ? assets : []).map(a => (
            <span className="asset-tag" key={a}>{a}</span>
          ))}
          {(!assets || assets.length === 0) && (
            <div style={{ color: 'var(--text2)' }}>No affected assets listed in extraction.</div>
          )}
        </div>
      </div>
    </div>
  )
}
