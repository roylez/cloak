# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
import Config

config :logger, :console,
  format: "$date $time $metadata[$level] $levelpad$message\n",
  metadata: [:port, :client],
  colors: [ enabled: true ]

config :cloak, env: config_env()

config :cloak, Cloak.MQTT,
  handler:   Cloak.MQTTHandler,
  topics:    ~w( board/+ port/+ port/+/SELF )

# It is also possible to import configuration files, relative to this
# directory. For example, you can emulate configuration per environment
# by uncommenting the line below and defining dev.exs, test.exs and such.
# Configuration from the imported file will override the ones defined
# here (which is why it is important to import them last).
#
import_config "_#{config_env()}.exs"
