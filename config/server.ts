import cronTasks from './cron-tasks';

export default ({ env }) => ({
  host: env('HOST', '0.0.0.0'),
  port: env.int('PORT', 1337),
   url: env('PUBLIC_URL', 'https://hidezoneofficial.onrender.com'), // <= ОБЯЗАТЕЛЬНО https
  proxy: true,
  cron: { enabled: true, tasks: cronTasks },
  app: { keys: env.array('APP_KEYS') },
});
