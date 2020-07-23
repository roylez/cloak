FROM elixir:1.10-alpine as builder

RUN apk update
RUN apk add libsodium libsodium-dev build-base git libtool autoconf automake
RUN mix local.hex --force && \
    mix local.rebar --force && \
    mix hex.info

WORKDIR /app
ENV MIX_ENV=prod
ADD . .

RUN mix deps.get
RUN mix release

# ==============================================

FROM alpine:3.11

ENV LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 LANGUAGE=en_US.UTF-8
ENV REPLACE_OS_VARS=true

RUN apk update --no-cache && \
    apk add --no-cache bash libsodium libssl1.1 ncurses-libs

WORKDIR /app

RUN addgroup -S cloak && adduser -S cloak -G cloak -h /app
USER cloak

COPY --chown=cloak:cloak --from=builder /app/_build/prod/rel/cloak .

CMD ["./bin/cloak", "start" ]
