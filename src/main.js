'use strict';

const { app, BrowserWindow, dialog, ipcMain, shell, safeStorage } = require('electron');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const { parseReportText } = require('./lib/scorecard');
const { VulnerabilityIntelService } = require('./lib/vuln-intel');

const MAX_JSON_BYTES = 25 * 1024 * 1024;
const MAX_FILES = 10000;
let mainWindow;
let pendingDirectory = findDirectoryArg(process.argv);
let intelService;

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

app.whenReady().then(async () => {
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
    // Ignore invalid OS open events.
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
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isAllowedExternalUrl(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (url !== mainWindow.webContents.getURL()) event.preventDefault();
  });
  mainWindow.webContents.once('did-finish-load', () => {
    if (pendingDirectory) {
      sendDirectory(pendingDirectory);
      pendingDirectory = null;
    }
  });
}

function registerIpc() {
  ipcMain.handle('directory:choose', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Choose a directory containing Scorecard JSON reports',
      properties: ['openDirectory']
    });
    return result.canceled ? null : result.filePaths[0];
  });

  ipcMain.handle('directory:scan', async (_event, request) => {
    const directory = await validateDirectory(request?.directory);
    return scanDirectory(directory, request?.recursive !== false);
  });

  ipcMain.handle('intel:enrich', async (event, identifiers) => {
    return intelService.enrich(identifiers, (progress) => {
      event.sender.send('intel:progress', progress);
    });
  });

  ipcMain.handle('intel:clear-cache', async () => {
    await intelService.clearCache();
    return true;
  });

  ipcMain.handle('settings:get', async () => {
    const settings = readSettings();
    return { hasGitHubToken: Boolean(settings.githubToken) };
  });

  ipcMain.handle('settings:set-github-token', async (_event, token) => {
    const cleanToken = String(token || '').trim();
    if (cleanToken && !safeStorage.isEncryptionAvailable()) {
      throw new Error('Secure credential storage is not available on this system. The token was not saved.');
    }
    const stored = readSettingsRaw();
    if (cleanToken) stored.githubTokenEncrypted = safeStorage.encryptString(cleanToken).toString('base64');
    else delete stored.githubTokenEncrypted;
    writeSettingsRaw(stored);
    return { hasGitHubToken: Boolean(cleanToken) };
  });

  ipcMain.handle('path:show', async (_event, filePath) => {
    const resolved = path.resolve(String(filePath || ''));
    shell.showItemInFolder(resolved);
    return true;
  });

  ipcMain.handle('external:open', async (_event, url) => {
    if (!isAllowedExternalUrl(url)) throw new Error('Blocked unsafe external URL.');
    await shell.openExternal(url);
    return true;
  });

  ipcMain.handle('export:csv', async (_event, csvText) => {
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Export Scorecard summary',
      defaultPath: 'scorecard-radar-export.csv',
      filters: [{ name: 'CSV', extensions: ['csv'] }]
    });
    if (result.canceled || !result.filePath) return null;
    await fs.writeFile(result.filePath, String(csvText || ''), 'utf8');
    return result.filePath;
  });
}

async function scanDirectory(directory, recursive) {
  const files = await findJsonFiles(directory, recursive);
  const reports = [];
  const errors = [];

  for (const filePath of files) {
    try {
      const stat = await fs.stat(filePath);
      if (stat.size > MAX_JSON_BYTES) {
        errors.push({ filePath, message: `Skipped: file is larger than ${MAX_JSON_BYTES / 1024 / 1024} MB.` });
        continue;
      }
      const text = await fs.readFile(filePath, 'utf8');
      const parsed = parseReportText(text, filePath);
      for (const report of parsed) {
        reports.push({
          ...report,
          date: report.date || stat.mtime.toISOString(),
          dateSource: report.date ? 'report' : 'file modified time',
          fileModifiedAt: stat.mtime.toISOString(),
          fileSize: stat.size
        });
      }
      if (!parsed.length) errors.push({ filePath, message: 'No recognizable Scorecard report object found.' });
    } catch (error) {
      errors.push({ filePath, message: error.message });
    }
  }

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
      const resolved = path.resolve(arg);
      if (fsSync.existsSync(resolved) && fsSync.statSync(resolved).isDirectory()) return resolved;
    } catch {
      // Ignore invalid command line paths.
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

function isAllowedExternalUrl(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === 'https:';
  } catch {
    return false;
  }
}

function settingsPath() {
  return path.join(app.getPath('userData'), 'settings.json');
}

function readSettingsRaw() {
  try {
    return JSON.parse(fsSync.readFileSync(settingsPath(), 'utf8'));
  } catch {
    return {};
  }
}

function readSettings() {
  const raw = readSettingsRaw();
  let githubToken = '';
  if (raw.githubTokenEncrypted && safeStorage.isEncryptionAvailable()) {
    try {
      githubToken = safeStorage.decryptString(Buffer.from(raw.githubTokenEncrypted, 'base64'));
    } catch {
      githubToken = '';
    }
  }
  return { githubToken };
}

function writeSettingsRaw(value) {
  const filePath = settingsPath();
  fsSync.mkdirSync(path.dirname(filePath), { recursive: true });
  const temp = `${filePath}.${process.pid}.tmp`;
  fsSync.writeFileSync(temp, JSON.stringify(value, null, 2), { mode: 0o600 });
  fsSync.renameSync(temp, filePath);
}
