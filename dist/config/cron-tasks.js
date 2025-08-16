"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = {
    pick_blackhole_winner: {
        task: async ({ strapi }) => {
            const now = new Date().toISOString();
            const due = await strapi.db
                .query('api::blackhole.blackhole')
                .findOne({
                where: { drawTime: { $lte: now }, $or: [
                        { allocated: { $eq: false } }, // нормальный false
                        { allocated: { $null: true } }, // null
                        { allocated: { $ne: true } }, // всё, что не true (на случай tinyint/строк)
                    ], },
                orderBy: { drawTime: 'desc' },
                select: ['id', 'participants', 'key']
            });
            if (!due) {
                strapi.log.debug('[cron] tick: no due draws');
                return;
            }
            const parts = Array.isArray(due.participants) ? due.participants : [];
            const winnerId = parts.length ? parts[Math.floor(Math.random() * parts.length)] : null;
            await strapi.db.query('api::blackhole.blackhole').update({
                where: { id: due.id },
                data: { allocated: true, winnerId }
            });
            if (winnerId) {
                const user = await strapi.entityService.findOne('plugin::users-permissions.user', winnerId, { fields: ['steamId'] });
                if (user === null || user === void 0 ? void 0 : user.steamId) {
                    await strapi.entityService.create('api::mail.mail', {
                        data: {
                            steamId: user.steamId,
                            type: 'new',
                            text: `<h1>Розыгрыш окончен!</h1><p>Ваш ключ: <b>${due.key}</b></p>`
                        }
                    });
                }
            }
            strapi.log.info(`[cron] blackhole#${due.id} → winner=${winnerId}`);
        },
        options: { rule: '* * * * *', tz: 'Asia/Tashkent' }, // каждую минуту
    },
};
