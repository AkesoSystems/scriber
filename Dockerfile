# Scriber (uzd-mvp) — образ для Coolify.
# Бекенд Express спавнить `claude -p` як підпроцес, тож Claude Code CLI має бути в образі.
# Авторизація headless — через змінну середовища CLAUDE_CODE_OAUTH_TOKEN (claude setup-token).
# НЕ запускати claude з --bare: у цьому режимі CLI ігнорує CLAUDE_CODE_OAUTH_TOKEN.
FROM node:22-bookworm-slim

# Claude Code CLI глобально. Node 18+; bookworm (glibc) — без musl/ripgrep-проблем Alpine.
RUN npm install -g @anthropic-ai/claude-code

# Непривілейований користувач: Claude Code відмовляється працювати від root без
# --dangerously-skip-permissions. $HOME має бути записуваним (CLI пише стан у ~/.claude).
RUN useradd -m -d /home/app -s /bin/bash app
ENV HOME=/home/app \
    DISABLE_AUTOUPDATER=1 \
    NODE_ENV=production \
    PORT=3000

WORKDIR /app

# Залежності окремим шаром для кешу.
COPY package*.json ./
RUN npm ci --omit=dev

# Решта коду. Сміття відсікає .dockerignore.
COPY . .

RUN chown -R app:app /app /home/app
USER app

EXPOSE 3000
CMD ["node", "server.js"]
