const { restoreAll, initR2 } = require('./src/services/r2-backup');

async function start() {
  // 第一步：先从 R2 恢复数据（在加载任何业务模块之前）
  if (initR2()) {
    await restoreAll();
  }

  // 第二步：恢复完成后再启动主程序
  require('./client.js');
}

start().catch((err) => {
  console.error('启动失败:', err);
  process.exit(1);
});
