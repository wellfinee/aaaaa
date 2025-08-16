// /src/admin/vite.config.js
const { mergeConfig } = require('vite');

module.exports = (config) => {
  return mergeConfig(config, {
    server: {
      // разрешаем именно этот хост
      allowedHosts: ['hidezoneofficial.com', 'api.hidezoneofficial.com'],
      // (при отладке можно сделать true, но это менее безопасно)
      // allowedHosts: true
    },
  });
};
