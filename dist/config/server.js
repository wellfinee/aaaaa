"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const cron_tasks_1 = __importDefault(require("./cron-tasks"));
exports.default = ({ env }) => ({
    host: env('HOST', '0.0.0.0'),
    port: env.int('PORT', 1337),
    url: env('PUBLIC_URL', 'http://hidezoneofficial.com'),
    proxy: true,
    cron: { enabled: true, tasks: cron_tasks_1.default },
    app: { keys: env.array('APP_KEYS') },
});
