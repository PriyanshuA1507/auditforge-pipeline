// const express = require('express')
// const multer = require('multer')
// const fetch = require('node-fetch')
// const cors = require('cors')
// const fs = require('fs')
// const path = require('path')

// // load .env if present
// try { require('dotenv').config() } catch (e) {}

// // ensure uploads directory exists to avoid ENOENT when streams open
// const uploadsDir = path.join(__dirname, 'uploads')
// if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true })

// const app = express()
// app.use(cors())

// const upload = multer({ dest: path.join(__dirname, 'uploads/') })

// const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_API_KEY
// if (!VIRUSTOTAL_KEY) {
//   console.warn('VIRUSTOTAL_API_KEY not set — server will return an error for scan requests')
// } else {
//   console.log('VIRUSTOTAL_API_KEY is configured (masked)')
// }

// // Upload endpoint: accepts a single file in `file` field and forwards to VirusTotal
// app.post('/scan', upload.single('file'), async (req, res) => {
//   if (!req.file) return res.status(400).json({ error: 'no file uploaded' })
//   console.log('Upload received:', { originalname: req.file.originalname, path: req.file.path, size: req.file.size, mimetype: req.file.mimetype })
//   try {
//     const listing = fs.readdirSync(uploadsDir)
//     console.log('uploads dir listing (first 50):', listing.slice(0, 50))
//   } catch (e) {
//     console.warn('failed to list uploads dir', String(e))
//   }
//   console.log('uploaded file exists:', fs.existsSync(req.file.path))
//   if (!VIRUSTOTAL_KEY) {
//     // Clean up
//     try { fs.unlinkSync(req.file.path) } catch (e) {}
//     return res.status(500).json({ error: 'VIRUSTOTAL_API_KEY not configured on server' })
//   }

//   // Try to extract CVE IDs from uploaded DOCX (best-effort)
//   let extractedCves = []
//   try {
//     console.log('Attempting CVE extraction for', req.file.path)
//     const name = req.file.originalname.toLowerCase()
//     if (name.endsWith('.docx') || (req.file.mimetype && req.file.mimetype.includes('off'))) {
//       const AdmZip = require('adm-zip')
//       const zip = new AdmZip(req.file.path)
//       const entries = zip.getEntries()
//       console.log('zip entries count:', entries.length)
//       let combined = ''
//       for (const e of entries) {
//         if (!e.entryName) continue
//         if (e.entryName.endsWith('.xml') || e.entryName.endsWith('.rels') || e.entryName.includes('word/')) {
//           try { combined += '\n' + zip.readAsText(e)
//           } catch (e) {}
//         }
//       }
//       const m = combined.match(/CVE-\d{4}-\d{4,7}/gi)
//       if (m && m.length) extractedCves = Array.from(new Set(m.map(x => x.toUpperCase())))
//     }
//   } catch (err) {
//     // non-fatal
//     console.warn('CVE extraction failed', String(err))
//   }

//   try {
//     if (!fs.existsSync(req.file.path)) {
//       return res.status(500).json({ error: 'uploaded file missing on server' })
//     }
//     let responded = false
//     const cleanupAndRespond = (status, body) => {
//       if (responded) return
//       responded = true
//       try { fs.unlinkSync(req.file.path) } catch (e) {}
//       try { res.status(status).json(body) } catch (e) {}
//     }

//     console.log('Creating read stream for', req.file.path)
//     const fileStream = fs.createReadStream(req.file.path)
//     fileStream.on('error', (err) => {
//       console.warn('fileStream error', String(err))
//       cleanupAndRespond(500, { error: 'file read error', details: String(err) })
//     })

//     const form = new (require('form-data'))()
//     form.append('file', fileStream, { filename: req.file.originalname })

//     // Submit file for analysis
//     const uploadResp = await fetch('https://www.virustotal.com/api/v3/files', {
//       method: 'POST',
//       headers: { 'x-apikey': VIRUSTOTAL_KEY },
//       body: form,
//     })

//     const uploadJson = await uploadResp.json().catch(err => ({ error: 'invalid json', details: String(err) }))
//     if (!uploadResp.ok) {
//       console.warn('VirusTotal upload failed', { status: uploadResp.status, body: uploadJson })
//       try { fs.unlinkSync(req.file.path) } catch (e) {}
//       return res.status(502).json({ error: 'virus total upload failed', status: uploadResp.status, details: uploadJson })
//     }

//     const analysisId = uploadJson.data && uploadJson.data.id
//     if (!analysisId) {
//       try { fs.unlinkSync(req.file.path) } catch (e) {}
//       return res.status(502).json({ error: 'no analysis id from virustotal', details: uploadJson })
//     }

//     // Poll analysis endpoint until completion or timeout
//     const start = Date.now()
//     const timeoutMs = 60_000 // 60s
//     let analysis = null
//     while (Date.now() - start < timeoutMs) {
//       const aResp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
//         headers: { 'x-apikey': VIRUSTOTAL_KEY }
//       })
//       const aJson = await aResp.json().catch(err => ({ error: 'invalid json', details: String(err) }))
//       if (aResp.ok) {
//         if (aJson.data && aJson.data.attributes && aJson.data.attributes.status === 'completed') {
//           analysis = aJson
//           break
//         }
//       } else {
//         console.warn('VirusTotal analysis fetch returned non-ok', { status: aResp.status, body: aJson })
//       }
//       // wait a bit
//       await new Promise(r => setTimeout(r, 2000))
//     }

//     // Clean up uploaded file
//     try { fs.unlinkSync(req.file.path) } catch (e) {}

//     if (responded) return // already responded in stream error handler
//     if (!analysis) return res.status(504).json({ error: 'analysis timeout' })

//     // Fetch file metadata (last_analysis_stats) if available to build vt_meta
//     let vt_meta = null
//     try {
//       const itemLink = analysis.data && analysis.data.links && analysis.data.links.item
//       if (itemLink) {
//         const fileResp = await fetch(itemLink, { headers: { 'x-apikey': VIRUSTOTAL_KEY } })
//         const fileJson = await fileResp.json().catch(e => ({ error: 'invalid json', details: String(e) }))
//         if (fileResp.ok && fileJson.data && fileJson.data.attributes) {
//           vt_meta = { stats: fileJson.data.attributes.last_analysis_stats || null, file: fileJson.data }
//         } else {
//           console.warn('Failed to fetch file metadata', { status: fileResp.status, body: fileJson })
//         }
//       }
//     } catch (e) {
//       console.warn('vt_meta fetch error', String(e))
//     }

//     // Return analysis summary, vt_meta, plus any extracted CVEs to client
//     return res.json({ analysis, vt_meta, extracted_cves: extractedCves })
//   } catch (err) {
//     try { fs.unlinkSync(req.file.path) } catch (e) {}
//     return res.status(500).json({ error: 'scan failed', details: String(err) })
//   }
// })

// const PORT = process.env.PORT || 4000
// app.listen(PORT, () => {
//   console.log(`Scan proxy listening on http://localhost:${PORT}`)
// })

const express = require('express')
const multer = require('multer')
const fetch = require('node-fetch')
const cors = require('cors')
const fs = require('fs')
const path = require('path')

// load .env if present
try { require('dotenv').config() } catch (e) {}

// ensure uploads directory exists to avoid ENOENT when streams open
const uploadsDir = path.join(__dirname, 'uploads')
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true })

const app = express()
app.use(cors())

// --- SECURE MULTER CONFIGURATION ---
const upload = multer({ 
  dest: path.join(__dirname, 'uploads/'),
  limits: { 
    fileSize: 50 * 1024 * 1024 // Strictly enforce 50 MB limit on the server
  },
  fileFilter: (req, file, cb) => {
    // Strictly enforce file types using Mime Types
    const allowedMimeTypes = [
      'application/pdf', 
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document' // DOCX
    ];

    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true); // Accept file
    } else {
      cb(new Error('SECURITY ALERT: Invalid file type. Only PDF and DOCX are allowed.')); // Reject file
    }
  }
})

const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_API_KEY
if (!VIRUSTOTAL_KEY) {
  console.warn('VIRUSTOTAL_API_KEY not set — server will return an error for scan requests')
} else {
  console.log('VIRUSTOTAL_API_KEY is configured (masked)')
}

// Upload endpoint: securely accepts a single file in `file` field and forwards to VirusTotal
app.post('/scan', (req, res, next) => {
  // Catch Multer errors (like file size limit or file type) before they hit the main route
  upload.single('file')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    next();
  });
}, async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no file uploaded' })
  
  console.log('Secure upload received and validated:', { 
    originalname: req.file.originalname, 
    path: req.file.path, 
    size: req.file.size, 
    mimetype: req.file.mimetype 
  })
  
  try {
    const listing = fs.readdirSync(uploadsDir)
    console.log('uploads dir listing (first 50):', listing.slice(0, 50))
  } catch (e) {
    console.warn('failed to list uploads dir', String(e))
  }
  
  console.log('uploaded file exists:', fs.existsSync(req.file.path))
  
  if (!VIRUSTOTAL_KEY) {
    // Clean up
    try { fs.unlinkSync(req.file.path) } catch (e) {}
    return res.status(500).json({ error: 'VIRUSTOTAL_API_KEY not configured on server' })
  }

  // Try to extract CVE IDs from uploaded DOCX (best-effort)
  let extractedCves = []
  try {
    console.log('Attempting CVE extraction for', req.file.path)
    const name = req.file.originalname.toLowerCase()
    if (name.endsWith('.docx') || (req.file.mimetype && req.file.mimetype.includes('off'))) {
      const AdmZip = require('adm-zip')
      const zip = new AdmZip(req.file.path)
      const entries = zip.getEntries()
      console.log('zip entries count:', entries.length)
      let combined = ''
      for (const e of entries) {
        if (!e.entryName) continue
        if (e.entryName.endsWith('.xml') || e.entryName.endsWith('.rels') || e.entryName.includes('word/')) {
          try { combined += '\n' + zip.readAsText(e)
          } catch (e) {}
        }
      }
      const m = combined.match(/CVE-\d{4}-\d{4,7}/gi)
      if (m && m.length) extractedCves = Array.from(new Set(m.map(x => x.toUpperCase())))
    }
  } catch (err) {
    // non-fatal
    console.warn('CVE extraction failed', String(err))
  }

  try {
    if (!fs.existsSync(req.file.path)) {
      return res.status(500).json({ error: 'uploaded file missing on server' })
    }
    let responded = false
    const cleanupAndRespond = (status, body) => {
      if (responded) return
      responded = true
      try { fs.unlinkSync(req.file.path) } catch (e) {}
      try { res.status(status).json(body) } catch (e) {}
    }

    console.log('Creating read stream for', req.file.path)
    const fileStream = fs.createReadStream(req.file.path)
    fileStream.on('error', (err) => {
      console.warn('fileStream error', String(err))
      cleanupAndRespond(500, { error: 'file read error', details: String(err) })
    })

    const form = new (require('form-data'))()
    form.append('file', fileStream, { filename: req.file.originalname })

    // Submit file for analysis
    const uploadResp = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: { 'x-apikey': VIRUSTOTAL_KEY },
      body: form,
    })

    const uploadJson = await uploadResp.json().catch(err => ({ error: 'invalid json', details: String(err) }))
    if (!uploadResp.ok) {
      console.warn('VirusTotal upload failed', { status: uploadResp.status, body: uploadJson })
      try { fs.unlinkSync(req.file.path) } catch (e) {}
      return res.status(502).json({ error: 'virus total upload failed', status: uploadResp.status, details: uploadJson })
    }

    const analysisId = uploadJson.data && uploadJson.data.id
    if (!analysisId) {
      try { fs.unlinkSync(req.file.path) } catch (e) {}
      return res.status(502).json({ error: 'no analysis id from virustotal', details: uploadJson })
    }

    // Poll analysis endpoint until completion or timeout
    const start = Date.now()
    const timeoutMs = 60_000 // 60s
    let analysis = null
    while (Date.now() - start < timeoutMs) {
      const aResp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': VIRUSTOTAL_KEY }
      })
      const aJson = await aResp.json().catch(err => ({ error: 'invalid json', details: String(err) }))
      if (aResp.ok) {
        if (aJson.data && aJson.data.attributes && aJson.data.attributes.status === 'completed') {
          analysis = aJson
          break
        }
      } else {
        console.warn('VirusTotal analysis fetch returned non-ok', { status: aResp.status, body: aJson })
      }
      // wait a bit
      await new Promise(r => setTimeout(r, 2000))
    }

    // Clean up uploaded file
    try { fs.unlinkSync(req.file.path) } catch (e) {}

    if (responded) return // already responded in stream error handler
    if (!analysis) return res.status(504).json({ error: 'analysis timeout' })

    // Fetch file metadata (last_analysis_stats) if available to build vt_meta
    let vt_meta = null
    try {
      const itemLink = analysis.data && analysis.data.links && analysis.data.links.item
      if (itemLink) {
        const fileResp = await fetch(itemLink, { headers: { 'x-apikey': VIRUSTOTAL_KEY } })
        const fileJson = await fileResp.json().catch(e => ({ error: 'invalid json', details: String(e) }))
        if (fileResp.ok && fileJson.data && fileJson.data.attributes) {
          vt_meta = { stats: fileJson.data.attributes.last_analysis_stats || null, file: fileJson.data }
        } else {
          console.warn('Failed to fetch file metadata', { status: fileResp.status, body: fileJson })
        }
      }
    } catch (e) {
      console.warn('vt_meta fetch error', String(e))
    }

    // Return analysis summary, vt_meta, plus any extracted CVEs to client
    return res.json({ analysis, vt_meta, extracted_cves: extractedCves })
  } catch (err) {
    try { fs.unlinkSync(req.file.path) } catch (e) {}
    return res.status(500).json({ error: 'scan failed', details: String(err) })
  }
})

const PORT = process.env.PORT || 4000
app.listen(PORT, () => {
  console.log(`Scan proxy listening on http://localhost:${PORT}`)
})
