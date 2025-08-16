// path: src/index.js
import passport from 'koa-passport';
import { Strategy as SteamStrategy } from 'passport-steam';
import axios from "axios"
import crypto from 'crypto';
export default {
  /**
   * Здесь мы подключаем сессии и passport до того,
   * как Strapi поднимет маршруты.
   */
  register({ strapi }) {
    const app = strapi.server.app;
    app.use(passport.initialize());
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
    passport.use(
      new SteamStrategy(
        {
          returnURL: `${process.env.APP_URL}/api/auth/steam/return`,
          realm: process.env.APP_URL,
          apiKey: process.env.STEAM_API_KEY,
        },
        async (identifier, profile, done) => {
          try {
            const steamId = profile.id.toString();
            let user = await strapi.db
              .query('plugin::users-permissions.user')
              .findOne({ where: { steamId } });

            if (!user) {
              const json = profile._json;
              user = await strapi.entityService.create(
                'plugin::users-permissions.user',
                {
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
                }
              );
            }
            done(null, user);
          } catch (err) {
            done(err);
          }
        }
      )
    );

    // 2) Сериализация / десериализация
    passport.serializeUser((user, done) => done(null, user.id));
    passport.deserializeUser(async (id, done) => {
      const user = await strapi.db
        .query('plugin::users-permissions.user')
        .findOne({ where: { id } });
      done(null, user);
    });
    // ИНИЦИАЦИЯ OAuth (stateless)
    router.get(
      '/api/auth/steam',
      passport.authenticate('steam', { session: false }) // важно!
    );

    // CALLBACK от Steam (stateless)
    router.get(
      '/api/auth/steam/return',
      passport.authenticate('steam', { session: false, failureRedirect: '/' }), // важно!
      async (ctx) => {
        try {
          strapi.log.info('→ GET /api/auth/steam/return');

          const profile = ctx.state.user;              // профиль от passport-steam
          const steamId = String(profile.id);

          // Найти пользователя по steamId (а не по primary id)
          const existed = await strapi.entityService.findMany(
            'plugin::users-permissions.user',
            { filters: { steamId }, limit: 1, fields: ['id', 'steamId'] }
          );

          let user = existed[0];
          if (user) {
            user = await strapi.entityService.update(
              'plugin::users-permissions.user',
              user.id,
              {
                data: {
                  username: profile.displayName,
                  avatar: profile.photos?.[2]?.value || profile.photos?.[0]?.value || null,
                }
              }
            );
            strapi.log.info(`   Updated user ID=${user.id}`);
          } else {
            user = await strapi.entityService.create(
              'plugin::users-permissions.user',
              {
                data: {
                  username: profile.displayName,
                  provider: 'steam',
                  confirmed: true,
                  blocked: false,
                  steamId,
                  avatar: profile.photos?.[2]?.value || profile.photos?.[0]?.value || null,
                }
              }
            );
            strapi.log.info(`   Created user ID=${user.id}`);
          }

          // Выпускаем JWT для user.id (а не profile.id)
          const jwt = strapi
            .plugin('users-permissions')
            .service('jwt')
            .issue({ id: user.id });

          // Ставим кросс-сайтовую secure-cookie (API: onrender, фронт: hidezoneofficial.com)
          ctx.cookies.set('jwt', jwt, {
            domain: "hidezoneofficial.onrender.com", // домен API
            httpOnly: true,
            secure: true,      // обязателен с SameSite=None
            sameSite: 'None',  // разные origin → нужна None
            maxAge: 24 * 60 * 60 * 1000,
            // domain и path НЕ указываем — кука принадлежит onrender-домену
          });
          strapi.log.info('   Cookie "jwt" set');

          // Редиректим на фронт
          const redirectUrl = 'https://hidezoneofficial.com/';
          ctx.redirect(redirectUrl);
        } catch (e) {
          strapi.log.error('Auth callback error:', e);
          ctx.redirect('/'); // запасной редирект
        }
      }
    );


    const MAIL_UID = 'api::mail.mail'; // заменишь на свой UID при необходимости

    // ---------- PATCH /api/mails/:id/mark-old ----------
    router.patch('/api/mails/:id/mark-old', async (ctx) => {
      // 1) Проверяем JWT из куки
      const token = ctx.cookies.get('jwt');
      if (!token) return ctx.unauthorized('Not authenticated');

      let userId;
      try {
        ({ id: userId } = await strapi
          .plugin('users-permissions')
          .service('jwt')
          .verify(token));
      } catch {
        return ctx.unauthorized('Invalid or expired token');
      }

      // 2) Достаём steamId пользователя
      const user = await strapi.entityService.findOne(
        'plugin::users-permissions.user',
        userId,
        { fields: ['id', 'steamId'] }
      );
      if (!user || !user.steamId) return ctx.unauthorized('User not found');

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
      if (String(msg.steamId) !== String(user.steamId)) {
        return ctx.forbidden('Not allowed');
      }

      // 6) Если уже old — ничего не меняем
      const currentType = (msg.type || '').trim().toLowerCase();
      if (currentType === 'old') {
        ctx.set('Cache-Control', 'no-store');
        ctx.body = { id: msg.id, type: msg.type, changed: false };
        return;
      }

      // 7) Обновляем на old
      const updated = await strapi.entityService.update(MAIL_UID, msgId, {
        data: { type: 'old' },
        fields: ['id', 'type'],
      });

      ctx.set('Cache-Control', 'no-store');
      ctx.body = { id: updated.id, type: updated.type, changed: true };
    });


    // ---------- GET /api/users/me ----------
    router.get('/api/users/me', async (ctx) => {
      // 1) Проверяем JWT из HttpOnly-куки
      const token = ctx.cookies.get('jwt');
      if (!token) return ctx.unauthorized('Not authenticated');

      let userId;
      try {
        ({ id: userId } = await strapi
          .plugin('users-permissions')
          .service('jwt')
          .verify(token));
      } catch {
        return ctx.unauthorized('Invalid or expired token');
      }

      // 2) Берём базового пользователя (id, steamId)
      const userRecord = await strapi.entityService.findOne(
        'plugin::users-permissions.user',
        userId,
        { fields: ['id', 'steamId', 'personaName', 'avatar', 'steamLevel', 'inWishlist'] }
      );
      if (!userRecord || !userRecord.steamId) return ctx.unauthorized('User not found');

      const steamId = String(userRecord.steamId);
      const apiKey = process.env.STEAM_API_KEY || '';
      const wishlistAppId = process.env.WISHLIST_APPID || '';

      // 3) Запрашиваем данные из Steam (best-effort)
      const updates: any = {};
      try {
        const http = axios.create({
          timeout: 7000,
          headers: { 'User-Agent': 'HideZone/1.0 (+https://hidezoneofficial.com)' },
        });

        if (apiKey) {
          const { data: sum } = await http.get(
            'https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/',
            { params: { key: apiKey, steamids: steamId } }
          );
          const player = sum?.response?.players?.[0];
          if (player) {
            updates.personaName = player.personaname || userRecord.personaName || null;
            updates.avatar = player.avatarfull || userRecord.avatar || null;
          }

          const { data: lvl } = await http.get(
            'https://api.steampowered.com/IPlayerService/GetSteamLevel/v1/',
            { params: { key: apiKey, steamid: steamId } }
          );
          if (lvl?.response?.player_level !== undefined) {
            updates.steamLevel = lvl.response.player_level;
          }
        }

        // wishlist (без ключа)
        if (wishlistAppId) {
          const { data: wl } = await http.get(
            `https://store.steampowered.com/wishlist/profiles/${steamId}/wishlistdata/`
          );
          updates.inWishlist = Object.prototype.hasOwnProperty.call(wl || {}, String(wishlistAppId));
        }
      } catch (e) {
        strapi.log.warn('Steam API failed, continue with partial data');
      }

      // 4) Обновляем пользователя, если есть что писать
      if (Object.keys(updates).length > 0) {
        try {
          await strapi.entityService.update(
            'plugin::users-permissions.user',
            userId,
            { data: updates }
          );
        } catch (e) {
          strapi.log.warn('User update skipped:', e?.message || e);
        }
      }

      // 5) Берём свежие данные пользователя
      const refreshed = await strapi.entityService.findOne(
        'plugin::users-permissions.user',
        userId,
        {
          fields: ['id', 'steamId', 'personaName', 'avatar', 'steamLevel', 'inWishlist']
        }
      );

      // 6) Почта: письма по steamId
      let mailsRaw = [];
      try {
        mailsRaw = await strapi.entityService.findMany(MAIL_UID, {
          filters: { steamId: { $eq: steamId } },
          fields: ['id', 'steamId', 'type', 'text', 'createdAt'],
          sort: [{ createdAt: 'desc' }],
          populate: {}, // если нужны связи — укажи тут
        });
      } catch (e) {
        strapi.log.error('Failed to load mails', e);
      }

      // 7) Украшаем письма для фронта
      const mails = (mailsRaw || []).map(m => {
        const t = (m.type || '').trim().toLowerCase();
        const isNew = t === 'new';
        return {
          id: m.id,
          text: m.text,
          type: m.type,
          createdAt: m.createdAt,
          isNew,
          color: isNew ? 'red' : 'gray',
        };
      });

      // 8) Ответ
      ctx.set('Cache-Control', 'no-store');
      ctx.body = {
        ...refreshed,
        mails,
      };
    });

    const KEYS_TABLE = 'game_keys';

    // Вероятность выигрыша: 0.05%  (100 / 200000)
    const CHANCE_NUMERATOR = 100;
    const CHANCE_DENOMINATOR = 200000;

    router.post('/api/spin', async (ctx) => {
      const nowIso = new Date().toISOString();
      strapi.log.info(`🎰 [spin] ip=${ctx.ip || 'unknown'} at ${nowIso}`);

      // 1) JWT из куки
      const token = ctx.cookies.get('jwt');
      if (!token) return ctx.unauthorized('Not authenticated');

      let userId;
      try {
        ({ id: userId } = await strapi
          .plugin('users-permissions')
          .service('jwt')
          .verify(token));
      } catch {
        return ctx.unauthorized('Invalid or expired token');
      }

      // 2) Берём steamId и lastSpinAt
      const userRecord = await strapi.entityService.findOne(
        'plugin::users-permissions.user',
        userId,
        { fields: ['steamId', 'lastSpinAt'] }
      );
      if (!userRecord || !userRecord.steamId) return ctx.unauthorized('User not found');

      const { steamId, lastSpinAt } = userRecord;

      // 2a) Кулдаун ровно 24 часа с момента прошлого спина
      if (lastSpinAt) {
        const last = new Date(lastSpinAt).getTime();
        const now = Date.now();
        const diffMs = now - last;
        const COOLDOWN_MS = 24 * 60 * 60 * 1000;
        if (diffMs < COOLDOWN_MS) {
          const remainMs = COOLDOWN_MS - diffMs;
          const remainMin = Math.ceil(remainMs / 60000);
          ctx.status = 400;
          ctx.body = { error: 'Вы уже крутили за последние 24 часа', minutesLeft: remainMin };
          return;
        }
      }

      // 3) Ролл и выдача ключа в одной транзакции
      const knex = strapi.db.connection;
      let won = false;
      let keyValue = null;

      try {
        await knex.transaction(async (trx) => {
          // Случайный шанс (0..DENOMINATOR-1)
          const roll = crypto.randomInt(0, CHANCE_DENOMINATOR);
          const isLucky = roll < CHANCE_NUMERATOR;

          if (!isLucky) return; // не повезло — просто выходим из транзакции

          // Берём первый свободный ключ под блокировкой
          const keyRow = await trx(KEYS_TABLE)
            .where({ allocated: false })
            .forUpdate()
            .first();

          if (!keyRow) {
            // Нет свободных ключей — выигрыша нет
            return;
          }

          // Пытаемся пометить как выданный (проверка на гонку в WHERE)
          const updatedCount = await trx(KEYS_TABLE)
            .where({ id: keyRow.id, allocated: false })
            .update({ allocated: true, steam_id: steamId, allocated_at: knex.fn.now() });

          if (updatedCount === 1) {
            won = true;
            keyValue = keyRow.key_value;
          }
          // если 0 — значит кто-то выхватил ключ параллельно, выигрыша нет
        });
      } catch (e) {
        strapi.log.error('spin tx failed:', e);
        ctx.status = 500;
        ctx.body = { error: 'Spin failed' };
        return;
      }

      // 4) Всегда фиксируем lastSpinAt
      try {
        await strapi.entityService.update(
          'plugin::users-permissions.user',
          userId,
          { data: { lastSpinAt: new Date() } }
        );
      } catch (e) {
        strapi.log.warn('failed to update lastSpinAt:', e?.message || e);
      }

      // 5) Если победа — письмо пользователю
      if (won && keyValue) {
        try {
          await strapi.entityService.create(MAIL_UID, {
            data: {
              steamId,
              type: 'new',
              text: `<h1>Вы выиграли ключ для игры</h1><h3 style="color:red">КЛЮЧ: ${keyValue}</h3>`,
            },
          });
        } catch (e) {
          strapi.log.error('failed to create mail:', e?.message || e);
        }
      }

      // 6) Ответ
      ctx.set('Cache-Control', 'no-store');
      ctx.body = { won, key: won ? keyValue : null };
    });

    // GET /api/spin/status
    router.get('/api/spin/status', async (ctx) => {
      const token = ctx.cookies.get('jwt');
      if (!token) return ctx.unauthorized('Not authenticated');
      let userId;
      try {
        ({ id: userId } = await strapi
          .plugin('users-permissions')
          .service('jwt')
          .verify(token));
      } catch {
        return ctx.unauthorized('Invalid or expired token');
      }

      // 2) Получаем steamId и lastSpinAt через entityService
      const userRecord = await strapi.entityService.findOne(
        'plugin::users-permissions.user',
        userId,
        { fields: ['steamId', 'lastSpinAt'] }
      );
      if (!userRecord) return ctx.unauthorized('User not found');

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
        secure: true,
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
      if (!token) return ctx.unauthorized('Not authenticated');
      let userId;
      try {
        ({ id: userId } = await strapi
          .plugin('users-permissions')
          .service('jwt')
          .verify(token));
      } catch {
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
      if (!token) return ctx.unauthorized('Not authenticated');
      let userId;
      try {
        ({ id: userId } = await strapi
          .plugin('users-permissions')
          .service('jwt')
          .verify(token));
      } catch {
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
