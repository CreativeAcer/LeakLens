/**
 * LeakLens Backend Server
 * Streams PowerShell scanner output to the frontend via Server-Sent Events (SSE)
 */

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const { spawn } = require('child_process');
const fs      = require('fs');
const os      = require('os');

const app  = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Serve frontend statically
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ─── Active scan tracking ──────────────────────────────────────────────────────
let activeScan = null; // { process, clients: Set }

// ─── SSE helper ───────────────────────────────────────────────────────────────
function sseWrite(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

// ─── GET /api/status ──────────────────────────────────────────────────────────
app.get('/api/status', (req, res) => {
  res.json({ scanning: activeScan !== null });
});

// ─── POST /api/scan ───────────────────────────────────────────────────────────
app.post('/api/scan', (req, res) => {
  if (activeScan) {
    return res.status(409).json({ error: 'A scan is already running.' });
  }

  const { scanPath, maxFileSizeMB = 10 } = req.body;
  if (!scanPath) {
    return res.status(400).json({ error: 'scanPath is required.' });
  }

  // Resolve the PowerShell script path
  const psScript = path.join(__dirname, 'scanner.ps1');

  // Determine PowerShell executable (cross-platform)
  const pwsh = os.platform() === 'win32' ? 'powershell.exe' : 'pwsh';

  const args = [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-File', psScript,
    '-ScanPath', scanPath,
    '-MaxFileSizeMB', String(maxFileSizeMB),
    '-JsonOutput'  // flag to make PS output NDJSON lines
  ];

  let proc;
  try {
    proc = spawn(pwsh, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    return res.status(500).json({ error: `Failed to start PowerShell: ${err.message}` });
  }

  activeScan = { process: proc, clients: new Set() };
  const clients = activeScan.clients;

  // Broadcast to all connected SSE clients
  function broadcast(event, data) {
    for (const client of clients) {
      sseWrite(client, event, data);
    }
  }

  let stdoutBuffer = '';

  proc.stdout.on('data', (chunk) => {
    stdoutBuffer += chunk.toString();
    const lines = stdoutBuffer.split('\n');
    stdoutBuffer = lines.pop(); // keep incomplete line

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      // Lines starting with JSON object → finding or progress
      if (trimmed.startsWith('{')) {
        try {
          const obj = JSON.parse(trimmed);
          if (obj.type === 'progress') {
            broadcast('progress', obj);
          } else if (obj.type === 'finding') {
            broadcast('finding', obj);
          } else if (obj.type === 'summary') {
            broadcast('summary', obj);
          }
        } catch (_) {
          broadcast('log', { message: trimmed });
        }
      } else {
        broadcast('log', { message: trimmed });
      }
    }
  });

  proc.stderr.on('data', (chunk) => {
    broadcast('error', { message: chunk.toString().trim() });
  });

  proc.on('close', (code) => {
    broadcast('done', { exitCode: code });
    // End all SSE connections
    for (const client of clients) {
      client.end();
    }
    activeScan = null;
  });

  res.json({ started: true });
});

// ─── POST /api/scan/stop ──────────────────────────────────────────────────────
app.post('/api/scan/stop', (req, res) => {
  if (!activeScan) {
    return res.status(404).json({ error: 'No active scan.' });
  }
  activeScan.process.kill();
  res.json({ stopped: true });
});

// ─── GET /api/stream ──────────────────────────────────────────────────────────
app.get('/api/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  if (!activeScan) {
    sseWrite(res, 'error', { message: 'No active scan. Start a scan first.' });
    res.end();
    return;
  }

  activeScan.clients.add(res);

  req.on('close', () => {
    if (activeScan) activeScan.clients.delete(res);
  });
});

// ─── GET /api/reports ─────────────────────────────────────────────────────────
app.get('/api/reports', (req, res) => {
  const reportsDir = path.join(__dirname, '..', 'reports');
  if (!fs.existsSync(reportsDir)) return res.json([]);

  const files = fs.readdirSync(reportsDir)
    .filter(f => f.endsWith('.json'))
    .map(f => {
      const stat = fs.statSync(path.join(reportsDir, f));
      return { name: f, size: stat.size, mtime: stat.mtime };
    })
    .sort((a, b) => b.mtime - a.mtime);

  res.json(files);
});

// ─── GET /api/reports/:name ───────────────────────────────────────────────────
app.get('/api/reports/:name', (req, res) => {
  const reportsDir = path.join(__dirname, '..', 'reports');
  const filePath = path.join(reportsDir, req.params.name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
  res.sendFile(filePath);
});

app.listen(PORT, () => {
  console.log(`\n  LeakLens backend running at http://localhost:${PORT}\n`);
});
