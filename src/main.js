'use strict';

const { app, BrowserWindow, dialog, ipcMain, shell, safeStorage } = require('electron');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { parseReportText } = require('./lib/scorecard');
const { VulnerabilityIntelService } = require('./lib/vuln-intel');
const {
  isPathWithin,
  isSafeHttpsUrl,
  normalizeIdentifiers,
  validateCsvText,
  validateGitHubToken
} = require('./lib/security');

const MAX_JSON_BYTES = 25 * 1024 * 1024;
const MAX_FILES = 10000;
const RENDERER_FILE = path.join(__dirname, 'renderer', 'index.html');
const RENDERER_URL = pathToFileURL(RENDERER_FILE).href;

let mainWindow;
let pendingDirectory = findDirectoryArg(process.argv);
let intelService;
let activeScanDirectory = '';
let allowedReportFiles = new Set();

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', (_event, argv) => {
    const directory = findDirectoryArg(argv);
    if (directory) sendDirectory(directory);
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

app.whenReady().then(() => {
  intelService = new VulnerabilityIntelService({
    cacheDir: path.join(app.getPath('userData'), 'intel-cache'),
    getGitHubToken: () => readSettings().githubToken || ''
  });

  createWindow();
  registerIpc();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('open-file', (event, filePath) => {
  event.preventDefault();
  try {
    if (fsSync.statSync(filePath).isDirectory()) sendDirectory(filePath);
  } catch {
    // Ignore invalid operating-system open events.
  }
});

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1480,
    height: 900,
    minWidth: 1040,
    minHeight: 680,
    title: 'Scorecard Radar',
    backgroundColor: '#0b1020',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      devTools: !app.isPackaged
    }
  });

  const session = mainWindow.webContents.session;
  session.setPermissionCheckHandler(() => false);
  session.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));

  mainWindow.loadFile(RENDERER_FILE);
  mainWindow.once('ready-to-show', () => mainWindow?.show());
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeHttpsUrl(url)) void shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-attach-webview', (event) => event.preventDefault());
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (url !== RENDERER_URL) event.preventDefault();
  });
  mainWindow.webContents.on('will-download', (event) => event.preventDefault());
  mainWindow.webContents.once('did-finish-load', () => {
    if (pendingDirectory) {
      sendDirectory(pendingDirectory);
      pendingDirectory = null;
    }
  });
}

function registerIpc() {
  handleTrusted('directory:choose', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Choose a directory containing Scorecard JSON reports',
      properties: ['openDirectory']
    });
    return result.canceled ? null : result.filePaths[0];
  });

  handleTrusted('directory:scan', async (_event, request) => {
    const directory = await validateDirectory(request?.directory);
    return scanDirectory(directory, request?.recursive !== false);
  });

  handleTrusted('intel:enrich', async (event, identifiers) => {
    const cleanIdentifiers = normalizeIdentifiers(identifiers);
    return intelService.enrich(cleanIdentifiers, (progress) => {
      if (!event.sender.isDestroyed()) event.sender.send('intel:progress', progress);
    });
  });

  handleTrusted('intel:clear-cache', async () => {
    await intelService.clearCache();
    return true;
  });

  handleTrusted('settings:get', async () => {
    const settings = readSettings();
    return { hasGitHubToken: Boolean(settings.githubToken) };
  });

  handleTrusted('settings:set-github-token', async (_event, token) => {
    const cleanToken = validateGitHubToken(token);
    if (cleanToken && !secureStorageAvailable()) {
      throw new Error('Secure credential storage is not available on this system. The token was not saved.');
    }
    const stored = readSettingsRaw();
    if (cleanToken) stored.githubTokenEncrypted = safeStorage.encryptString(cleanToken).toString('base64');
    else delete stored.githubTokenEncrypted;
    writeSettingsRaw(stored);
    return { hasGitHubToken: Boolean(cleanToken) };
  });

  handleTrusted('path:show', async (_event, filePath) => {
    const resolved = await fs.realpath(path.resolve(String(filePath || '')));
    if (!activeScanDirectory || !isPathWithin(activeScanDirectory, resolved) || !allowedReportFiles.has(resolved)) {
      throw new Error('The requested file is not part of the active scan.');
    }
    shell.showItemInFolder(resolved);
    return true;
  });

  handleTrusted('external:open', async (_event, url) => {
    if (!isSafeHttpsUrl(url)) throw new Error('Blocked unsafe external URL.');
    await shell.openExternal(String(url));
    return true;
  });

  handleTrusted('export:csv', async (_event, csvText) => {
    const cleanCsv = validateCsvText(csvText);
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Export Scorecard summary',
      defaultPath: 'scorecard-radar-export.csv',
      filters: [{ name: 'CSV', extensions: ['csv'] }]
    });
    if (result.canceled || !result.filePath) return null;
    await fs.writeFile(result.filePath, cleanCsv, { encoding: 'utf8', mode: 0o600 });
    return result.filePath;
  });
}

function handleTrusted(channel, handler) {
  ipcMain.handle(channel, async (event, ...args) => {
    assertTrustedSender(event);
    return handler(event, ...args);
  });
}

function assertTrustedSender(event) {
  const senderUrl = event.senderFrame?.url || event.sender?.getURL?.() || '';
  if (!mainWindow || event.sender !== mainWindow.webContents || senderUrl !== RENDERER_URL) {
    throw new Error('Rejected IPC call from an untrusted renderer.');
  }
}

async function scanDirectory(directory, recursive) {
  const files = await findJsonFiles(directory, recursive);
  const reports = [];
  const errors = [];
  const authorizedFiles = new Set();

  for (const filePath of files) {
    try {
      const realFilePath = await fs.realpath(filePath);
      if (!isPathWithin(directory, realFilePath)) {
        errors.push({ filePath, message: 'Skipped: resolved path is outside the selected directory.' });
        continue;
      }
      const stat = await fs.stat(realFilePath);
      if (stat.size > MAX_JSON_BYTES) {
        errors.push({ filePath: realFilePath, message: `Skipped: file is larger than ${MAX_JSON_BYTES / 1024 / 1024} MB.` });
        continue;
      }
      const text = await fs.readFile(realFilePath, 'utf8');
      const parsed = parseReportText(text, realFilePath);
      for (const report of parsed) {
        reports.push({
          ...report,
          date: report.date || stat.mtime.toISOString(),
          dateSource: report.date ? 'report' : 'file modified time',
          fileModifiedAt: stat.mtime.toISOString(),
          fileSize: stat.size
        });
      }
      authorizedFiles.add(realFilePath);
      if (!parsed.length) errors.push({ filePath: realFilePath, message: 'No recognizable Scorecard report object found.' });
    } catch (error) {
      errors.push({ filePath, message: safeErrorMessage(error) });
    }
  }

  activeScanDirectory = directory;
  allowedReportFiles = authorizedFiles;
  return { directory, reports, errors, fileCount: files.length, scannedAt: new Date().toISOString() };
}

async function findJsonFiles(directory, recursive) {
  const output = [];
  const queue = [directory];
  while (queue.length) {
    const current = queue.shift();
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory() && recursive) queue.push(fullPath);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith('.json')) output.push(fullPath);
      if (output.length >= MAX_FILES) throw new Error(`Stopped after ${MAX_FILES} JSON files. Narrow the selected directory.`);
    }
  }
  return output.sort((a, b) => a.localeCompare(b));
}

async function validateDirectory(value) {
  if (!value) throw new Error('No directory selected.');
  const resolved = await fs.realpath(path.resolve(String(value)));
  const stat = await fs.stat(resolved);
  if (!stat.isDirectory()) throw new Error('The selected path is not a directory.');
  return resolved;
}

function findDirectoryArg(argv) {
  for (const arg of argv.slice(1)) {
    if (!arg || arg.startsWith('-')) continue;
    try {
      const resolved = fsSync.realpathSync(path.resolve(arg));
      if (fsSync.statSync(resolved).isDirectory()) return resolved;
    } catch {
      // Ignore invalid command-line paths.
    }
  }
  return null;
}

function sendDirectory(directory) {
  if (mainWindow?.webContents && !mainWindow.webContents.isLoading()) {
    mainWindow.webContents.send('directory:requested', directory);
  } else {
    pendingDirectory = directory;
  }
}

function settingsPath() {
  return path.join(app.getPath('userData'), 'settings.json');
}

function readSettingsRaw() {
  try {
    const parsed = JSON.parse(fsSync.readFileSync(settingsPath(), 'utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function readSettings() {
  const raw = readSettingsRaw();
  let githubToken = '';
  if (typeof raw.githubTokenEncrypted === 'string' && secureStorageAvailable()) {
    try {
      githubToken = validateGitHubToken(safeStorage.decryptString(Buffer.from(raw.githubTokenEncrypted, 'base64')));
    } catch {
      githubToken = '';
    }
  }
  return { githubToken };
}

function secureStorageAvailable() {
  if (!safeStorage.isEncryptionAvailable()) return false;
  if (process.platform === 'linux' && typeof safeStorage.getSelectedStorageBackend === 'function') {
    return safeStorage.getSelectedStorageBackend() !== 'basic_text';
  }
  return true;
}

function writeSettingsRaw(value) {
  const filePath = settingsPath();
  fsSync.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  fsSync.writeFileSync(temp, JSON.stringify(value, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  fsSync.renameSync(temp, filePath);
  try {
    fsSync.chmodSync(filePath, 0o600);
  } catch {
    // Windows and some filesystems do not expose POSIX modes.
  }
}

function safeErrorMessage(error) {
  return error instanceof Error && error.message ? error.message : 'Unknown scan error.';
}
