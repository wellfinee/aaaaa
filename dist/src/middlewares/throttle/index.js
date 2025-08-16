"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const koa2_ratelimit_1 = require("koa2-ratelimit");
exports.default = (_config, { strapi }) => {
    // 1) 1× в сутки — POST /api/spin
    const spinLimiter = koa2_ratelimit_1.RateLimit.middleware({
        interval: 24 * 60 * 60 * 1000,
        max: 3,
        message: 'Можно крутить только раз в 24 часа',
        keyGenerator: ctx => ctx.cookies.get('jwt') || ctx.ip,
    });
    // 2) 1× в 20 минут — POST /api/blackhole/search
    const searchLimiter = koa2_ratelimit_1.RateLimit.middleware({
        interval: 20 * 60 * 1000,
        max: 10,
        message: 'Можно искать ключ не чаще, чем раз в 20 минут',
        keyGenerator: ctx => ctx.cookies.get('jwt') || ctx.ip,
    });
    // 3) Все остальные API — 1× в 0.5 секунды
    const defaultLimiter = koa2_ratelimit_1.RateLimit.middleware({
        interval: 60 * 1000,
        max: 200,
        message: 'Подождите полсекунды перед следующим запросом',
        keyGenerator: ctx => ctx.ip,
    });
    // Сам middleware-фабрика
    return async (ctx, next) => {
        const { method, path } = ctx.request;
        // 🚀 0) Сразу пропускаем всё, что не начинается с /api/
        //     — в том числе все пути /admin/* и статику
        if (!path.startsWith('/api/')) {
            return next();
        }
        // 1) /api/spin
        if (method === 'POST' && path === '/api/spin') {
            return spinLimiter(ctx, next);
        }
        // 2) /api/blackhole/search
        if (method === 'POST' && path === '/api/blackhole/search') {
            return searchLimiter(ctx, next);
        }
        // 3) Любые другие /api/* запросы
        return defaultLimiter(ctx, next);
    };
};
