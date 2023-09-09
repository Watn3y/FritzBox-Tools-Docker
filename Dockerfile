# syntax=docker/dockerfile:1
FROM php:8.1-cli-alpine
WORKDIR /app

ENV COMMIT=${COMMIT}

RUN apk update
RUN apk upgrade --available
RUN apk add curl

RUN curl -sSL "https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions" -o - | sh -s bz2 mcrypt hash openssl mysqli sqlite3 

ADD fb_tools.php fb_tools.php

ENTRYPOINT ["php", "/app/fb_tools.php"]
