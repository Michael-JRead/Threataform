/**
 * Threataform — Electron Main Process
 *
 * Launches Vite dev server output in a desktop window.
 * Serves .gguf model files from the /models directory via a local HTTP server
 * so wllama can load them without a file picker.
 *
 * Usage:
 *   1. Place your GGUF file in /models (e.g. models/Llama-3.2-3B-Instruct-Q4_K_M.gguf)
 *   2. npm run dev  →  Vite + Electron start together
 *   3. App detects Electron and auto-loads the first .gguf found in /models
 */

const { app, BrowserWindow, ipcMain } = require('electron');
const path  = require('path');
const http  = require('http');
const fs    = require('fs');

// ── Config ────────────────────────────────────────────────────────────────────
const VITE_URL    = 'http://127.0.0.1:5173';
const MODELS_DIR  = path.join(__dirname, '..', 'models');
const MODEL_PORT  = 27177; // Fixed port → stable URL → wllama OPFS cache works correctly

// ── State ─────────────────────────────────────────────────────────────────────
let modelServer     = null;
let modelServerPort = 0;
let availableModels = [];

// ── Model HTTP Server ─────────────────────────────────────────────────────────
// Serves GGUF files from /models with full Range-request support.
// wllama uses Range requests for progressive streaming — required for large models.
function startModelServer() {
  return new Promise((resolve, reject) => {
    // Scan models directory for .gguf files
    availableModels = [];
    if (fs.existsSync(MODELS_DIR)) {
      availableModels = fs.readdirSync(MODELS_DIR)
        .filter(f => f.toLowerCase().endsWith('.gguf') && !f.startsWith('.'));
    }

    modelServer = http.createServer((req, res) => {
      // CORS — renderer (http://127.0.0.1:5173) needs to fetch from this server
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Range');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      if (req.url === '/models') {
        // List available models as JSON
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(availableModels));
        return;
      }

      // Serve model file
      const filename = decodeURIComponent(path.basename(req.url.split('?')[0]));
      const filePath = path.join(MODELS_DIR, filename);

      // Security: only serve files that were in our scanned list
      if (!availableModels.includes(filename) || !fs.existsSync(filePath)) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }

      const stat = fs.statSync(filePath);
      const rangeHeader = req.headers['range'];

      if (rangeHeader) {
        // Range request — required for wllama progressive loading
        const match = rangeHeader.match(/bytes=(\d+)-(\d*)/);
        if (!match) {
          res.writeHead(416, { 'Content-Range': `bytes */${stat.size}` });
          res.end();
          return;
        }
        const start = parseInt(match[1], 10);
        const end   = match[2] ? parseInt(match[2], 10) : stat.size - 1;
        const chunk = end - start + 1;

        res.writeHead(206, {
          'Content-Range':  `bytes ${start}-${end}/${stat.size}`,
          'Accept-Ranges':  'bytes',
          'Content-Length': chunk,
          'Content-Type':   'application/octet-stream',
        });
        fs.createReadStream(filePath, { start, end }).pipe(res);
      } else {
        // Full file
        res.writeHead(200, {
          'Content-Type':   'application/octet-stream',
          'Content-Length': stat.size,
          'Accept-Ranges':  'bytes',
        });
        fs.createReadStream(filePath).pipe(res);
      }
    });

    // Try fixed port first; if taken, fall back to any available port
    modelServer.listen(MODEL_PORT, '127.0.0.1', () => {
      modelServerPort = modelServer.address().port;
      console.log(`[Threataform] Model server → http://127.0.0.1:${modelServerPort}`);
      console.log(`[Threataform] Available models: ${availableModels.length ? availableModels.join(', ') : '(none — place .gguf files in /models)'}`);
      resolve();
    });

    modelServer.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        // Port taken — use any available port
        modelServer.listen(0, '127.0.0.1', () => {
          modelServerPort = modelServer.address().port;
          console.log(`[Threataform] Port ${MODEL_PORT} in use, using ${modelServerPort} instead`);
          console.warn('[Threataform] Warning: non-fixed port means wllama OPFS cache may not persist between sessions');
          resolve();
        });
      } else {
        reject(err);
      }
    });
  });
}

// ── IPC handlers ──────────────────────────────────────────────────────────────
// Renderer calls these via window.electronAPI
ipcMain.handle('get-model-info', () => ({
  port:   modelServerPort,
  models: availableModels,
}));

// ── Main window ───────────────────────────────────────────────────────────────
async function createWindow() {
  await startModelServer();

  const win = new BrowserWindow({
    width:  1440,
    height: 900,
    title:  'Threataform',
    webPreferences: {
      preload:          path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration:  false,
      // No webSecurity: false needed — model served from localhost, same as renderer origin
    },
  });

  // Load Vite dev server
  win.loadURL(VITE_URL);

  // Open DevTools in dev mode (comment out to hide)
  // win.webContents.openDevTools();
}

// ── App lifecycle ─────────────────────────────────────────────────────────────
app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (modelServer) modelServer.close();
  app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
