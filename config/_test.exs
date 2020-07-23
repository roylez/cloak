use Mix.Config

config :logger, level: :error

config :cloak,
  command_port: 7004

config :cloak, Cloak.MQTT,
  client_id: { :system, "CLOAK_MQTT_CLIENT", "cloak_test" }
