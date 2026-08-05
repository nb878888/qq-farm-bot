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

// 只备份这3个核心配置文件
const BACKUP_FILES = ['store.json', 'accounts.json', 'users.json'];

let backupTimer = null;

// ==================== AWS Signature V4 签名（纯原生） ====================
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

// 从 endpoint 里解析出 host 和 path
function parseEndpoint(endpoint) {
  const url = new URL(endpoint);
  return {
    host: url.host,
    protocol: url.protocol,
  };
}

/**
 * 发送 S3 兼容请求
 * @param {object} opts
 * @param {string} opts.method - HTTP 方法
 * @param {string} opts.key - 对象 key
 * @param {Buffer|null} opts.body - 请求体
 * @param {string} opts.endpoint - R2 endpoint
 * @param {string} opts.accessKeyId
 * @param {string} opts.secretAccessKey
 * @param {string} opts.bucket
 * @returns {Promise<{statusCode:number, headers:object, body:Buffer}>}
 */
function s3Request({ method, key, body = null, endpoint, accessKeyId, secretAccessKey, bucket }) {
  return new Promise((resolve, reject) => {
    const { host, protocol } = parseEndpoint(endpoint);
    const region = 'auto';
    const service = 's3';
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);

    const canonicalUri = `/${bucket}/${encodeURIComponent(key).replace(/%2F/g, '/')}`;
    const canonicalQuerystring = '';
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
      path: canonicalUri,
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

// ==================== R2 操作封装 ====================
function getR2Config() {
  const endpoint = process.env.R2_ENDPOINT;
  const accessKeyId = process.env.R2_ACCESS_KEY_ID;
  const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
  if (!endpoint || !accessKeyId || !secretAccessKey) return null;
  return { endpoint, accessKeyId, secretAccessKey, bucket: R2_BUCKET };
}

async function uploadFile(filename) {
  const cfg = getR2Config();
  if (!cfg) return false;

  const dataDir = getDataDir();
  const localPath = path.join(dataDir, filename);
  if (!fs.existsSync(localPath)) return false;

  try {
    const content = fs.readFileSync(localPath);
    const key = `${R2_PREFIX}${filename}`;
    const res = await s3Request({
      method: 'PUT',
      key,
      body: content,
      ...cfg,
    });
    return res.statusCode >= 200 && res.statusCode < 300;
  } catch (err) {
    console.error(`[R2] 上传失败 ${filename}:`, err.message);
    return false;
  }
}

async function downloadFile(filename) {
  const cfg = getR2Config();
  if (!cfg) return false;

  try {
    const key = `${R2_PREFIX}${filename}`;
    const res = await s3Request({
      method: 'GET',
      key,
      body: null,
      ...cfg,
    });

    if (res.statusCode === 404) return false;
    if (res.statusCode < 200 || res.statusCode >= 300) return false;

    const dataDir = ensureDataDir();
    const localPath = path.join(dataDir, filename);
    fs.writeFileSync(localPath, res.body);
    return true;
  } catch (err) {
    console.error(`[R2] 下载失败 ${filename}:`, err.message);
    return false;
  }
}

// ==================== 批量备份/恢复 ====================
async function backupAll(reason = 'manual') {
  if (!R2_ENABLED || !getR2Config()) return { ok: false };

  let successCount = 0;
  for (const filename of BACKUP_FILES) {
    if (await uploadFile(filename)) {
      successCount++;
    }
  }

  console.log(`[R2] 备份完成 (${reason}): ${successCount}/${BACKUP_FILES.length} 个文件`);
  return { ok: true, successCount, total: BACKUP_FILES.length };
}

async function restoreAll() {
  if (!R2_ENABLED || !getR2Config()) return { ok: false };

  let successCount = 0;
  for (const filename of BACKUP_FILES) {
    if (await downloadFile(filename)) {
      successCount++;
    }
  }

  console.log(`[R2] 恢复完成: ${successCount}/${BACKUP_FILES.length} 个文件`);
  return { ok: true, successCount, total: BACKUP_FILES.length };
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
