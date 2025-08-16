"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const koa_passport_1 = __importDefault(require("koa-passport"));
const passport_steam_1 = require("passport-steam");
const axios_1 = __importDefault(require("axios"));
const crypto_1 = __importDefault(require("crypto"));
exports.default = {
    /**
     * Здесь мы подключаем сессии и passport до того,
     * как Strapi поднимет маршруты.
     */
    register({ strapi }) {
        const app = strapi.server.app;
        // Ключи для подписи куки-сессий
        // Инициализируем Passport
        app.use(koa_passport_1.default.initialize());
    },
    /**
     * В bootstrap-фазе настраиваем стратегию,
     * сериализацию и маршруты.
     */
    bootstrap({ strapi }) {
        const enabled = strapi.config.get('server.cron.enabled');
        if (!enabled) {
            strapi.log.warn('[cron] disabled: enable it in config/server.ts');
            return;
        }
        const { app, router } = strapi.server;
        // 1) Настраиваем SteamStrategy
        koa_passport_1.default.use(new passport_steam_1.Strategy({
            returnURL: `${process.env.APP_URL}/api/auth/steam/return`,
            realm: process.env.APP_URL,
            apiKey: process.env.STEAM_API_KEY,
        }, async (identifier, profile, done) => {
            try {
                const steamId = profile.id.toString();
                let user = await strapi.db
                    .query('plugin::users-permissions.user')
                    .findOne({ where: { steamId } });
                if (!user) {
                    const json = profile._json;
                    user = await strapi.entityService.create('plugin::users-permissions.user', {
                        data: {
                            username: profile.displayName || `SteamUser${steamId}`,
                            steamId,
                            provider: 'steam',
                            email: `${steamId}@steam.fake`,
                            confirmed: true,
                            blocked: false,
                            avatarUrl: json.avatarfull,
                            profileUrl: json.profileurl,
                            realName: json.realname,
                            countryCode: json.loccountrycode,
                        },
                    });
                }
                done(null, user);
            }
            catch (err) {
                done(err);
            }
        }));
        // 2) Сериализация / десериализация
        koa_passport_1.default.serializeUser((user, done) => done(null, user.id));
        koa_passport_1.default.deserializeUser(async (id, done) => {
            const user = await strapi.db
                .query('plugin::users-permissions.user')
                .findOne({ where: { id } });
            done(null, user);
        });
        router.get('/api/auth/steam', koa_passport_1.default.authenticate('steam'));
        // 3) Маршруты аутентификации
        router.get('/api/auth/steam/return', koa_passport_1.default.authenticate('steam', { failureRedirect: '/' }), async (ctx) => {
            var _a, _b, _c, _d;
            strapi.log.info('→ GET /api/auth/steam/return');
            const profile = ctx.state.user;
            const steamId = String(profile.id);
            // Найти или создать
            const existing = await strapi.entityService.findOne('plugin::users-permissions.user', steamId, { fields: ['id', 'steamId'] });
            strapi.log.info(existing.id);
            let user;
            if (existing) {
                strapi.log.info(`   Updating user ID=${existing.id}`);
                user = await strapi.entityService.update('plugin::users-permissions.user', existing.id, { data: { username: profile.displayName, avatar: (_b = (_a = profile.photos) === null || _a === void 0 ? void 0 : _a[2]) === null || _b === void 0 ? void 0 : _b.value } });
                strapi.log.info(`1 ${existing}`);
            }
            else {
                strapi.log.info('   Creating new user');
                user = await strapi.entityService.create('plugin::users-permissions.user', {
                    data: {
                        username: profile.displayName,
                        provider: 'steam',
                        confirmed: true,
                        blocked: false,
                        steamId,
                        avatar: ((_d = (_c = profile.photos) === null || _c === void 0 ? void 0 : _c[2]) === null || _d === void 0 ? void 0 : _d.value) || null,
                    }
                });
                strapi.log.info(`2 ${existing}`);
            }
            // Создать JWT
            const jwt = strapi
                .plugin('users-permissions')
                .service('jwt')
                .issue({ id: profile.id });
            strapi.log.info(`   JWT issued for user ID=${user.id}`);
            // Поставить куку
            ctx.cookies.set('jwt', jwt, {
                domain: "hidezoneofficial.onrender.com",
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'None',
                maxAge: 24 * 60 * 60 * 1000,
            });
            strapi.log.info('   Cookie "jwt" set');
            // Редирект на фронт
            const redirectUrl = 'https://hidezoneofficial.com/';
            ctx.redirect(redirectUrl);
        });
        const MAIL_UID = 'api::mail.mail'; // заменишь на свой UID при необходимости
        // ---------- PATCH /api/mails/:id/mark-old ----------
        router.patch('/api/mails/:id/mark-old', async (ctx) => {
            // 1) Проверяем JWT из куки
            const token = ctx.cookies.get('jwt');
            if (!token)
                return ctx.unauthorized('Not authenticated');
            let userId;
            try {
                ({ id: userId } = await strapi
                    .plugin('users-permissions')
                    .service('jwt')
                    .verify(token));
            }
            catch {
                return ctx.unauthorized('Invalid or expired token');
            }
            // 2) Достаём steamId пользователя
            const user = await strapi.entityService.findOne('plugin::users-permissions.user', userId, { fields: ['id', 'steamId'] });
            if (!user)
                return ctx.unauthorized('User not found');
            // 3) Валидация id
            const msgId = Number(ctx.params.id);
            if (!Number.isInteger(msgId) || msgId <= 0) {
                ctx.status = 400;
                ctx.body = { error: 'Invalid message id' };
                return;
            }
            // 4) Ищем письмо
            const msg = await strapi.entityService.findOne(MAIL_UID, msgId, {
                fields: ['id', 'steamId', 'type'],
            });
            if (!msg) {
                ctx.status = 404;
                ctx.body = { error: 'Message not found' };
                return;
            }
            // 5) Авторизация: письмо должно принадлежать этому пользователю
            if (msg.steamId !== user.steamId) {
                return ctx.forbidden('Not allowed');
            }
            // 6) Если уже old — ничего не меняем
            if ((msg.type || '').toLowerCase() === 'old') {
                ctx.body = { id: msg.id, type: msg.type, changed: false };
                return;
            }
            // 7) Обновляем на old
            const updated = await strapi.entityService.update(MAIL_UID, msgId, {
                data: { type: 'old' },
            });
            ctx.body = { id: updated.id, type: updated.type, changed: true };
        });
        router.get('/api/users/me', async (ctx) => {
            var _a;
            // 1) Проверяем JWT из HttpOnly‑куки
            const token = ctx.cookies.get('jwt');
            if (!token)
                return ctx.unauthorized('Not authenticated');
            let userId;
            try {
                ({ id: userId } = await strapi
                    .plugin('users-permissions')
                    .service('jwt')
                    .verify(token));
            }
            catch {
                return ctx.unauthorized('Invalid or expired token');
            }
            // 2) Берём базового пользователя (id, steamId)
            const userRecord = await strapi.entityService.findOne('plugin::users-permissions.user', userId, { fields: ['id', 'steamId'] });
            if (!userRecord)
                return ctx.unauthorized('User not found');
            const { steamId } = userRecord;
            const apiKey = process.env.STEAM_API_KEY;
            const wishlistAppId = process.env.WISHLIST_APPID;
            // 3) Запрашиваем данные из Steam (best-effort)
            const updates = {};
            try {
                const { data: sum } = await axios_1.default.get('https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/', { params: { key: apiKey, steamids: steamId } });
                const player = (_a = sum.response.players) === null || _a === void 0 ? void 0 : _a[0];
                if (player) {
                    updates.personaName = player.personaname;
                    updates.avatar = player.avatarfull;
                }
                const { data: lvl } = await axios_1.default.get('https://api.steampowered.com/IPlayerService/GetSteamLevel/v1/', { params: { key: apiKey, steamid: steamId } });
                updates.steamLevel = lvl.response.player_level;
                const { data: wl } = await axios_1.default.get(`https://store.steampowered.com/wishlist/profiles/${steamId}/wishlistdata/`);
                updates.inWishlist = Object.prototype.hasOwnProperty.call(wl, wishlistAppId);
            }
            catch (e) {
                strapi.log.warn('Steam API failed, continue with partial data');
            }
            // 4) Обновляем пользователя, если есть что писать
            if (Object.keys(updates).length > 0) {
                await strapi.entityService.update('plugin::users-permissions.user', userId, { data: updates });
            }
            // 5) Берём свежие данные пользователя
            const refreshed = await strapi.entityService.findOne('plugin::users-permissions.user', userId, {
                fields: ['id', 'steamId', 'personaName', 'avatar', 'steamLevel', 'inWishlist']
            });
            // 6) ТА САМАЯ ПОЧТА: все письма по steamId из вашей коллекции
            // !!! Замените 'api::mail.mail' на UID вашей коллекции
            let mailsRaw = [];
            try {
                mailsRaw = await strapi.entityService.findMany('api::mail.mail', {
                    filters: { steamId: { $eq: steamId } }, // ищем все письма этого человека
                    fields: ['id', 'steamId', 'type', 'text', 'createdAt'],
                    sort: [{ createdAt: 'desc' }],
                });
            }
            catch (e) {
                strapi.log.error('Failed to load mails', e);
            }
            // 7) Украшаем письма для фронта: isNew + color
            const mails = mailsRaw.map(m => {
                const isNew = (m.type || '').toLowerCase() === 'new';
                return {
                    id: m.id,
                    text: m.text,
                    type: m.type,
                    createdAt: m.createdAt,
                    isNew,
                    color: isNew ? 'red' : 'gray',
                };
            });
            // 8) Возвращаем всё вместе
            ctx.body = {
                ...refreshed,
                mails,
            };
        });
        router.post('/api/spin', async (ctx) => {
            // В src/index.ts внутри POST /api/blackhole/search
            strapi.log.info(`🔍 [blackhole/search] запрос от ${ctx.ip || 'anonymous'} в ${new Date().toISOString()}`);
            // 1) Верифицируем JWT
            const token = ctx.cookies.get('jwt');
            if (!token)
                return ctx.unauthorized('Not authenticated');
            let userId;
            try {
                ({ id: userId } = await strapi
                    .plugin('users-permissions')
                    .service('jwt')
                    .verify(token));
            }
            catch {
                return ctx.unauthorized('Invalid or expired token');
            }
            // 2) Получаем steamId и lastSpinAt через entityService
            const userRecord = await strapi.entityService.findOne('plugin::users-permissions.user', userId, { fields: ['steamId', 'lastSpinAt'] });
            if (!userRecord)
                return ctx.unauthorized('User not found');
            const { steamId, lastSpinAt } = userRecord;
            const today = new Date().toISOString().slice(0, 10);
            if (lastSpinAt && lastSpinAt.slice(0, 10) === today) {
                return ctx.badRequest('Вы уже крутите сегодня');
            }
            // 3) Логика «крутилки» в транзакции: блокируем только game_keys
            const knex = strapi.db.connection;
            const MAX = 200;
            const WIN_COUNT = 200; // шанс 100/200000 = 0.05%
            let won = false;
            let keyValue;
            await knex.transaction(async (trx) => {
                // Crypto‐рандом
                const roll = crypto_1.default.randomInt(0, MAX);
                if (roll < WIN_COUNT) {
                    // берём первый незанятый ключ
                    const keyRow = await trx('game_keys')
                        .where({ allocated: false })
                        .forUpdate()
                        .first();
                    if (keyRow) {
                        won = true;
                        keyValue = keyRow.key_value;
                        await trx('game_keys')
                            .where({ id: keyRow.id })
                            .update({ allocated: true, steam_id: steamId });
                    }
                }
            });
            // 4) Обновляем lastSpinAt через entityService
            await strapi.entityService.update('plugin::users-permissions.user', userId, { data: { lastSpinAt: new Date() } });
            // 5) Если выиграли — записываем в mail
            if (won && keyValue) {
                await strapi.entityService.create('api::mail.mail', {
                    data: {
                        steamId,
                        type: 'new',
                        text: `<h1>Вы выиграли ключ для игры</h1><h3 style="color: red">КЛЮЧ: ${keyValue}</h3>`,
                    },
                });
            }
            // 6) Отправляем ответ клиенту
            ctx.body = { won, key: keyValue };
        });
        // GET /api/spin/status
        router.get('/api/spin/status', async (ctx) => {
            const token = ctx.cookies.get('jwt');
            if (!token)
                return ctx.unauthorized('Not authenticated');
            let userId;
            try {
                ({ id: userId } = await strapi
                    .plugin('users-permissions')
                    .service('jwt')
                    .verify(token));
            }
            catch {
                return ctx.unauthorized('Invalid or expired token');
            }
            // 2) Получаем steamId и lastSpinAt через entityService
            const userRecord = await strapi.entityService.findOne('plugin::users-permissions.user', userId, { fields: ['steamId', 'lastSpinAt'] });
            if (!userRecord)
                return ctx.unauthorized('User not found');
            const { lastSpinAt } = userRecord;
            const today = new Date().toISOString().slice(0, 10);
            if (lastSpinAt && lastSpinAt.slice(0, 10) === today) {
                return ctx.badRequest('Вы уже крутите сегодня');
            }
            ctx.body = { canSpin: true };
        });
        // GET /api/spin/history
        router.get('/api/spin/history', async (ctx) => {
            const wins = await strapi.entityService.findMany('api::mail.mail', {
                filters: { type: { $eq: 'win' } },
                sort: [{ createdAt: 'desc' }],
                fields: ['steamId', 'text', 'createdAt'],
            });
            ctx.body = wins;
        });
        router.get('/api/auth/logout', async (ctx) => {
            strapi.log.info('→ GET /api/auth/logout');
            const cookieOptions = {
                domain: "hidezoneofficial.onrender.com",
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'None',
                maxAge: 0,
            };
            ctx.cookies.set('jwt', null, { ...cookieOptions, path: '/' });
            ctx.cookies.set('jwt', null, { ...cookieOptions, path: '/api' });
            strapi.log.info('   jwt cookie cleared');
            ctx.redirect('https://hidezoneofficial.com/');
        });
        router.post('/api/blackhole/register', async (ctx) => {
            // 1) Auth
            const token = ctx.cookies.get('jwt');
            if (!token)
                return ctx.unauthorized('Not authenticated');
            let userId;
            try {
                ({ id: userId } = await strapi
                    .plugin('users-permissions')
                    .service('jwt')
                    .verify(token));
            }
            catch {
                return ctx.unauthorized('Invalid or expired token');
            }
            // 2) Find next draw (drawTime > now, allocated = false)
            const now = new Date().toISOString();
            const next = await strapi.db
                .query('api::blackhole.blackhole')
                .findOne({
                where: { drawTime: { $gt: now } },
                orderBy: { drawTime: 'asc' },
                select: ['id', 'participants', 'drawTime']
            });
            if (!next) {
                return ctx.send({ status: 'no_draw', message: 'No upcoming draw' });
            }
            // 3) Add userId to participants (JSON array)
            const parts = Array.isArray(next.participants) ? next.participants : [];
            if (!parts.includes(userId)) {
                parts.push(userId);
                await strapi.db
                    .query('api::blackhole.blackhole')
                    .update({
                    where: { id: next.id },
                    data: { participants: parts }
                });
            }
            // 4) Return drawTime for front-end timer
            ctx.send({
                status: 'registered',
                drawTime: next.drawTime,
            });
        });
        // ─── GET /api/blackhole/status ───────────────────────────────────────
        router.get('/api/blackhole/status', async (ctx) => {
            // 1) Auth
            const token = ctx.cookies.get('jwt');
            if (!token)
                return ctx.unauthorized('Not authenticated');
            let userId;
            try {
                ({ id: userId } = await strapi
                    .plugin('users-permissions')
                    .service('jwt')
                    .verify(token));
            }
            catch {
                return ctx.unauthorized('Invalid or expired token');
            }
            const nowTs = Date.now();
            const now = new Date(nowTs).toISOString();
            // 2) Find the next upcoming draw
            const future = await strapi.db
                .query('api::blackhole.blackhole')
                .findOne({
                where: { drawTime: { $gt: now } },
                orderBy: { drawTime: 'asc' },
                select: ['drawTime', 'participants']
            });
            if (future) {
                const parts = Array.isArray(future.participants) ? future.participants : [];
                return ctx.send({
                    active: true,
                    finished: false,
                    registered: parts.includes(userId),
                    drawTime: future.drawTime,
                    won: null,
                    key: null
                });
            }
            // 3) Find the last past draw
            const past = await strapi.db
                .query('api::blackhole.blackhole')
                .findOne({
                where: { drawTime: { $lte: now } },
                orderBy: { drawTime: 'desc' },
                select: ['id', 'drawTime', 'allocated', 'participants', 'winnerId', 'key']
            });
            if (!past) {
                return ctx.send({
                    active: false,
                    finished: null,
                    registered: null,
                    drawTime: null,
                    won: null,
                    key: null,
                    message: 'No draws scheduled'
                });
            }
            const drawTs = new Date(past.drawTime).getTime();
            const age = nowTs - drawTs;
            const TTL = 3 * 60 * 60 * 1000; // 3 hours
            const parts = Array.isArray(past.participants) ? past.participants : [];
            const registered = parts.includes(userId);
            // 4) If not yet allocated and within 3h window → waiting
            if (!past.allocated && age < TTL) {
                return ctx.send({
                    active: false,
                    finished: false,
                    registered,
                    drawTime: past.drawTime,
                    won: null,
                    key: null,
                    message: 'Awaiting result'
                });
            }
            // 5) If past TTL → hide draw
            if (age >= TTL) {
                return ctx.send({
                    active: false,
                    finished: null,
                    registered: null,
                    drawTime: null,
                    won: null,
                    key: null,
                    message: 'Draw expired'
                });
            }
            // 6) allocated = true → return result
            const won = past.winnerId == userId;
            return ctx.send({
                active: false,
                finished: true,
                registered,
                drawTime: past.drawTime,
                won,
                key: won ? past.key : null
            });
        });
        // mount routes
        strapi.server.app
            .use(router.routes())
            .use(router.allowedMethods());
        app.use(router.routes()).use(router.allowedMethods());
    },
};
