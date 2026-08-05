const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const https = require('node:https');
const { getDataDir, ensureDataDir } = require('../config/runtime-paths');

// ==================== 配置 ====================
const R2_ENABLED = process.env.R2_ENABLED === 'true';
const R2_BUCKET = process.env.R2_BUCKET || 'qq-farm-bot-data';
const R2_SITE_ID = process.env.R2_SITE_ID || 'site1';
const R2_PREFIX = `${R2_SITE_ID}/`;
const BACKUP_INTERVAL_MS = Number(process.env.R2_BACKUP_INTERVAL || 15) * 60 * 1000;

// 备份清单：3个文件 + 3个缓存目录
const BACKUP_FILES = ['store.json', 'accounts.json', 'users.json'];
const BACKUP_DIRS = ['known_friend_gids', 'friend_dog_info', 'friend_list_cache'];

let backupTimer = null;

// ==================== AWS Signature V4 ====================
function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function getSignatureKey(key, dateStamp, region, service) {
  const kDate = hmac(`AWS4${key}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, 'aws4_request');
  return kSigning;
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function parseEndpoint(endpoint) {
  const url = new URL(endpoint);
  return { host: url.host, protocol: url.protocol };
}

function s3Request({ method, key, body = null, query = '', endpoint, accessKeyId, secretAccessKey, bucket }) {
  return new Promise((resolve, reject) => {
    const { host } = parseEndpoint(endpoint);
    const region = 'auto';
    const service = 's3';
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);

    const canonicalUri = `/${bucket}/${encodeURIComponent(key).replace(/%2F/g, '/')}`;
    const canonicalQuerystring = query;
    const payloadHash = body ? sha256(body) : sha256('');

    const canonicalHeaders =
      `host:${host}\n` +
      `x-amz-content-sha256:${payloadHash}\n` +
      `x-amz-date:${amzDate}\n`;

    const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';

    const canonicalRequest =
      `${method}\n` +
      `${canonicalUri}\n` +
      `${canonicalQuerystring}\n` +
      `${canonicalHeaders}\n` +
      `${signedHeaders}\n` +
      `${payloadHash}`;

    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign =
      `${algorithm}\n` +
      `${amzDate}\n` +
      `${credentialScope}\n` +
      `${sha256(canonicalRequest)}`;

    const signingKey = getSignatureKey(secretAccessKey, dateStamp, region, service);
    const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

    const authorizationHeader =
      `${algorithm} Credential=${accessKeyId}/${credentialScope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const options = {
      hostname: host,
      path: canonicalUri + (query ? `?${query}` : ''),
      method,
      headers: {
        'Host': host,
        'x-amz-date': amzDate,
        'x-amz-content-sha256': payloadHash,
        'Authorization': authorizationHeader,
      },
    };

    if (body) {
      options.headers['Content-Length'] = body.length;
    }

    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks),
        });
      });
    });

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ==================== R2 基础操作 ====================
function getR2Config() {
  const endpoint = process.env.R2_ENDPOINT;
  const accessKeyId = process.env.R2_ACCESS_KEY_ID;
  const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
  if (!endpoint || !accessKeyId || !secretAccessKey) return null;
  return { endpoint, accessKeyId, secretAccessKey, bucket: R2_BUCKET };
}

// 列出指定前缀下的所有对象
async function listObjects(prefix) {
  const cfg = getR2Config();
  if (!cfg) return [];

  const allKeys = [];
  let continuationToken = null;

  do {
    const queryParams = ['list-type=2', `prefix=${encodeURIComponent(prefix)}`];
    if (continuationToken) {
      queryParams.push(`continuation-token=${encodeURIComponent(continuationToken)}`);
    }
    const query = queryParams.join('&');

    const res = await s3Request({
      method: 'GET',
      key: '',
      body: null,
      query,
      ...cfg,
    });

    if (res.statusCode < 200 || res.statusCode >= 300) break;

    // 解析 XML 提取 Key
    const xml = res.body.toString('utf8');
    const keyMatches = xml.match(/<Key>([^<]+)<\/Key>/g);
    if (keyMatches) {
      for (const m of keyMatches) {
        const key = m.replace(/<\/?Key>/g, '');
        if (!key.endsWith('/')) allKeys.push(key);
      }
    }

    const nextTokenMatch = xml.match(/<NextContinuationToken>([^<]+)<\/NextContinuationToken>/);
    continuationToken = nextTokenMatch ? nextTokenMatch[1] : null;

    const isTruncated = xml.includes('<IsTruncated>true</IsTruncated>');
    if (!isTruncated) break;
  } while (continuationToken);

  return allKeys;
}

async function uploadObject(key, localPath) {
  const cfg = getR2Config();
  if (!cfg) return false;
  if (!fs.existsSync(localPath)) return false;

  try {
    const content = fs.readFileSync(localPath);
    const res = await s3Request({
      method: 'PUT',
      key,
      body: content,
      ...cfg,
    });
    return res.statusCode >= 200 && res.statusCode < 300;
  } catch (err) {
    console.error(`[R2] 上传失败 ${key}:`, err.message);
    return false;
  }
}

async function downloadObject(key, localPath) {
  const cfg = getR2Config();
  if (!cfg) return false;

  try {
    const res = await s3Request({
      method: 'GET',
      key,
      body: null,
      ...cfg,
    });

    if (res.statusCode === 404) return false;
    if (res.statusCode < 200 || res.statusCode >= 300) return false;

    // 确保目录存在
    const dir = path.dirname(localPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(localPath, res.body);
    return true;
  } catch (err) {
    console.error(`[R2] 下载失败 ${key}:`, err.message);
    return false;
  }
}

// ==================== 文件/目录递归操作 ====================
function getAllFilesInDir(dirPath) {
  const result = [];
  if (!fs.existsSync(dirPath)) return result;

  const items = fs.readdirSync(dirPath);
  for (const item of items) {
    const fullPath = path.join(dirPath, item);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      result.push(...getAllFilesInDir(fullPath));
    } else {
      result.push(fullPath);
    }
  }
  return result;
}

async function uploadFile(filename) {
  const dataDir = getDataDir();
  const localPath = path.join(dataDir, filename);
  const r2Key = `${R2_PREFIX}${filename}`;
  return uploadObject(r2Key, localPath);
}

async function uploadDir(dirname) {
  const dataDir = getDataDir();
  const dirPath = path.join(dataDir, dirname);
  const files = getAllFilesInDir(dirPath);
  let successCount = 0;

  for (const filePath of files) {
    const relativePath = path.relative(dataDir, filePath).replace(/\\/g, '/');
    const r2Key = `${R2_PREFIX}${relativePath}`;
    if (await uploadObject(r2Key, filePath)) {
      successCount++;
    }
  }

  return successCount;
}

async function downloadFile(filename) {
  const dataDir = ensureDataDir();
  const localPath = path.join(dataDir, filename);
  const r2Key = `${R2_PREFIX}${filename}`;
  return downloadObject(r2Key, localPath);
}

async function downloadDir(dirname) {
  const dataDir = ensureDataDir();
  const prefix = `${R2_PREFIX}${dirname}/`;
  const keys = await listObjects(prefix);
  let successCount = 0;

  for (const key of keys) {
    const relativePath = key.slice(R2_PREFIX.length);
    const localPath = path.join(dataDir, relativePath);
    if (await downloadObject(key, localPath)) {
      successCount++;
    }
  }

  return successCount;
}

// ==================== 批量备份/恢复 ====================
async function backupAll(reason = 'manual') {
  if (!R2_ENABLED || !getR2Config()) return { ok: false };

  let fileSuccess = 0;
  let dirSuccess = 0;
  let dirTotalFiles = 0;

  // 备份文件
  for (const filename of BACKUP_FILES) {
    if (await uploadFile(filename)) fileSuccess++;
  }

  // 备份目录
  for (const dirname of BACKUP_DIRS) {
    const count = await uploadDir(dirname);
    dirSuccess += count > 0 ? 1 : 0;
    dirTotalFiles += count;
  }

  console.log(`[R2] 备份完成 (${reason}): 文件 ${fileSuccess}/${BACKUP_FILES.length}，目录 ${dirSuccess}/${BACKUP_DIRS.length}（共 ${dirTotalFiles} 个缓存文件）`);
  return { ok: true, fileSuccess, dirSuccess, dirTotalFiles };
}

async function restoreAll() {
  if (!R2_ENABLED || !getR2Config()) return { ok: false };

  let fileSuccess = 0;
  let dirSuccess = 0;
  let dirTotalFiles = 0;

  // 恢复文件
  for (const filename of BACKUP_FILES) {
    if (await downloadFile(filename)) fileSuccess++;
  }

  // 恢复目录
  for (const dirname of BACKUP_DIRS) {
    const count = await downloadDir(dirname);
    dirSuccess += count > 0 ? 1 : 0;
    dirTotalFiles += count;
  }

  console.log(`[R2] 恢复完成: 文件 ${fileSuccess}/${BACKUP_FILES.length}，目录 ${dirSuccess}/${BACKUP_DIRS.length}（共 ${dirTotalFiles} 个缓存文件）`);
  return { ok: true, fileSuccess, dirSuccess, dirTotalFiles };
}

// ==================== 定时备份 & 优雅退出 ====================
function startScheduledBackup() {
  if (!R2_ENABLED || !getR2Config()) return;
  if (backupTimer) return;

  backupTimer = setInterval(() => {
    backupAll('scheduled').catch(() => {});
  }, BACKUP_INTERVAL_MS);

  console.log(`[R2] 定时备份已启动，间隔 ${BACKUP_INTERVAL_MS / 60000} 分钟`);
}

function stopScheduledBackup() {
  if (backupTimer) {
    clearInterval(backupTimer);
    backupTimer = null;
  }
}

function setupGracefulShutdown() {
  if (!R2_ENABLED || !getR2Config()) return;

  const shutdown = async (signal) => {
    console.log(`[R2] 收到 ${signal}，备份中...`);
    stopScheduledBackup();
    try {
      await backupAll(`shutdown-${signal.toLowerCase()}`);
    } catch (err) {
      console.error('[R2] 退出时备份失败:', err.message);
    }
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

function initR2() {
  if (!R2_ENABLED) return false;
  const cfg = getR2Config();
  if (!cfg) {
    console.warn('[R2] 环境变量不完整，跳过');
    return false;
  }
  console.log(`[R2] 已启用，站点: ${R2_SITE_ID}，Bucket: ${R2_BUCKET}`);
  return true;
}

// ==================== 导出 ====================
module.exports = {
  initR2,
  backupAll,
  restoreAll,
  startScheduledBackup,
  stopScheduledBackup,
  setupGracefulShutdown,
  isR2Enabled: () => R2_ENABLED && !!getR2Config(),
};
