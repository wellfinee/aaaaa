"use strict";
// config/middlewares.js
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = [
    // 1) Обработка ошибок
    'strapi::errors',
    // 2) Парсинг query-параметров
    'strapi::query',
    // 3) Кастомный throttle для API
    {
        resolve: './src/middlewares/throttle',
        config: {},
    },
    // 4) Общая безопасность + CSP + глобальный rateLimit
    {
        name: 'strapi::security',
        config: {
            // Clickjacking
            frameguard: { action: 'deny' },
            // HSTS — принудительный HTTPS
            hsts: {
                maxAge: 31536000,
                includeSubDomains: true,
                preload: true,
            },
            // XSS-фильтр браузера
            xssFilter: true,
            // Блокировать «угадай MIME» в браузерах
            xContentTypeOptions: true,
            // CSP: разрешаем inline-скрипты и стили
            contentSecurityPolicy: {
                useDefaults: true,
                directives: {
                    "default-src": ["'self'"],
                    "script-src": ["'self'", "'unsafe-inline'", "https:"],
                    "style-src": ["'self'", "'unsafe-inline'", "https:"],
                    "img-src": ["'self'", "data:", "blob:", "https:"],
                    "connect-src": ["'self'", "https:"],
                    "font-src": ["'self'", "data:", "https:"],
                    "frame-ancestors": ["'none'"],
                    // добавьте media-src, object-src и т.д. по необходимости
                },
            },
            // Referrer-Policy
            referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
            // Permissions-Policy (Feature-Policy)
            permissionsPolicy: {
                geolocation: [],
                camera: [],
                microphone: [],
            },
            // Expect-CT (Certificate Transparency)
            expectCt: {
                maxAge: 86400,
                enforce: true,
                reportUri: '/report-ct',
            },
            // Глобальный rateLimit для всего прочего (1 запрос / 3 сек)
            rateLimit: {
                interval: 3 * 1000,
                max: 1,
                message: 'Подождите пару секунд перед следующим запросом',
            },
        },
    },
    // 5) CORS
    {
        name: 'strapi::cors',
        config: {
            origin: ['https://hidezoneofficial.com', 'https://api.hidezoneofficial.com'],
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        },
    },
    // 6) Ограничение размера тела запроса
    {
        name: 'strapi::body',
        config: {
            jsonLimit: '1mb',
            formLimit: '1mb',
            textLimit: '1mb',
            formidable: { maxFileSize: 200 * 1024 * 1024 },
        },
    },
    // 7) Сессии Koa
    {
        name: 'strapi::session',
        config: {
            key: 'koa.sess',
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            secureProxy: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            domain: 'hidezoneofficial.com',
            maxAge: 24 * 60 * 60 * 1000,
        },
    },
    // 8) Favicon и публичная статика
    'strapi::favicon',
    'strapi::public',
];
