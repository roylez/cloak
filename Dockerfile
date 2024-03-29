ARG erlang_version=24.0.2
ARG elixir_version=1.12.1
ARG alpine_version=3.13.3

FROM hexpm/elixir:${elixir_version}-erlang-${erlang_version}-alpine-${alpine_version} AS builder

RUN apk update
RUN apk add build-base git libtool autoconf automake rust cargo
RUN mix local.hex --force && \
    mix local.rebar --force && \
    mix hex.info

WORKDIR /app
ENV MIX_ENV=prod RUSTLER_NIF_VERSION=2.15
ADD . .

RUN mix deps.get
RUN mix release

# ==============================================

FROM alpine:${alpine_version}


ENV LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 LANGUAGE=en_US.UTF-8

# iputils is required for ping command
RUN apk update --no-cache && \
    apk add --no-cache bash libsodium libssl1.1 ncurses-libs libgcc libstdc++ iputils

WORKDIR /app

RUN addgroup -S cloak && adduser -S cloak -G cloak -h /app
USER cloak

COPY --chown=cloak:cloak --from=builder /app/_build/prod/rel/cloak .

CMD ["./bin/cloak", "start" ]
