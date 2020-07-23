export hostname := $(shell hostname)

.PHONY: iex
iex:
	iex --name cloak@${hostname}.local -S mix

.PHONY: docker
docker:
	docker build -t cloak .
