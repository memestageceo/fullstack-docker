FROM node:alpine
WORKDIR /home/app

COPY package.json .
# COPY pnpm-lock.json .

RUN npm install -g pnpm

RUN pnpm install

COPY . .

EXPOSE 5173

CMD ["pnpm", "run", "dev"]
