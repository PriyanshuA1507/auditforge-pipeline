import React from 'react'

function JsonLine({ text }) {
  const parts = []
  let remaining = text

  const keyMatch = remaining.match(/^(\\s*)\"([^\"]+)\": ?/)
  if (keyMatch) {
    parts.push(<span key="indent">{keyMatch[1]}</span>)
    parts.push(<span key="key" className="json-key">{`"${keyMatch[2]}"`}</span>)
    parts.push(<span key="colon">: </span>)
    remaining = remaining.slice(keyMatch[0].length)
  }

  if (/^"/.test(remaining)) {
    const m = remaining.match(/^"([^"]*)"(,?)$/)
    if (m) {
      parts.push(<span key="vs" className="json-str">{`"${m[1]}"`}</span>)
      parts.push(<span key="vc">{m[2]}</span>)
      remaining = ''
    }
  } else if (/^-?\d/.test(remaining)) {
    const m = remaining.match(/^(-?[\d.]+)(,?)$/)
    if (m) {
      parts.push(<span key="vn" className="json-num">{m[1]}</span>)
      parts.push(<span key="vc">{m[2]}</span>)
      remaining = ''
    }
  } else if (/^(true|false)/.test(remaining)) {
    const m = remaining.match(/^(true|false)(,?)$/)
    if (m) {
      parts.push(<span key="vb" className="json-bool">{m[1]}</span>)
      parts.push(<span key="vc">{m[2]}</span>)
      remaining = ''
    }
  }

  if (remaining) parts.push(<span key="rem">{remaining}</span>)
  return <div>{parts}</div>
}

export default function JsonOutput({ data }) {
  const lines = JSON.stringify(data, null, 2).split('\n')
  return (
    <div className="json-output">
      {lines.map((line, i) => <JsonLine key={i} text={line} />)}
    </div>
  )
}
