# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
use Mix.Config

# This configuration is loaded before any dependency and is restricted
# to this project. If another project depends on this project, this
# file won't be loaded nor affect the parent project. For this reason,
# if you want to provide default values for your application for
# 3rd-party users, it should be done in your "mix.exs" file.

# You can configure for your application as:
#
#     config :cloak, key: :value
#
# And access this configuration in your application as:
#
#     Application.get_env(:cloak, :key)
#
# Or configure a 3rd-party app:
#
#     config :logger, level: :info
#
config :logger, :console,
  format: "$date $time $metadata[$level] $levelpad$message\n",
  colors: [ enabled: true ]

config :cloak,
  env: Mix.env(),
  enable_static: { :system, :boolean,  "CLOAK_ENABLE_STATIC", true  },
  enable_mqtt:   { :system, :boolean,  "CLOAK_ENABLE_MQTT",   false },
  enable_trojan: { :system, :boolean,  "CLOAK_ENABLE_TROJAN", false }

config :cloak, :trojan,
  port:   { :system, :integer, "CLOAK_TROJAN_PORT",   2000 },
  cacertfile:  { :system, "CLOAK_TROJAN_CACERT",      "./ssl/chain.pem"   },
  certfile:    { :system, "CLOAK_TROJAN_CERT",        "./ssl/cert.pem"    },
  keyfile:     { :system, "CLOAK_TROJAN_KEY",         "./ssl/privkey.pem" },
  fake_server: { :system, "CLOAK_TROJAN_FAKE_SERVER", "127.0.0.1"         },
  fake_server_port:  { :system, :integer, "CLOAK_TROJAN_FAKE_SERVER_PORT", 80 }

config :cloak, Cloak.MQTT,
  handler:   Cloak.MQTTHandler,
  topics:    ~w( board/+ port/+ port/+/SELF ),
  host:      { :system, "CLOAK_MQTT_HOST",     "localhost" },
  client_id: { :system, "CLOAK_MQTT_CLIENT",   ""          },
  user_name: { :system, "CLOAK_MQTT_USERNAME", "cloak"     },
  password:  { :system, "CLOAK_MQTT_PASSWORD", "cloak"     }

# It is also possible to import configuration files, relative to this
# directory. For example, you can emulate configuration per environment
# by uncommenting the line below and defining dev.exs, test.exs and such.
# Configuration from the imported file will override the ones defined
# here (which is why it is important to import them last).
#
import_config "_#{Mix.env}.exs"
