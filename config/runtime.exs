import Config

config :cloak,
  enable_static: System.get_env("CLOAK_ENABLE_STATIC", "1") != "0",
  enable_mqtt:   System.get_env("CLOAK_ENABLE_MQTT",   "0") != "0",
  enable_trojan: System.get_env("CLOAK_ENABLE_TROJAN", "0") != "0"

config :cloak, :trojan,
  port:        String.to_integer(System.get_env("CLOAK_TROJAN_PORT", "2000" )),
  cacertfile:  System.get_env( "CLOAK_TROJAN_CACERT",      "./ssl/chain.pem"   ),
  certfile:    System.get_env( "CLOAK_TROJAN_CERT",        "./ssl/cert.pem"    ),
  keyfile:     System.get_env( "CLOAK_TROJAN_KEY",         "./ssl/privkey.pem" ),
  fake_server: System.get_env( "CLOAK_TROJAN_FAKE_SERVER", "127.0.0.1"         ),
  fake_server_port: String.to_integer(System.get_env( "CLOAK_TROJAN_FAKE_SERVER_PORT", "80" ))

config :cloak, Cloak.MQTT,
  host:      System.get_env( "CLOAK_MQTT_HOST",     "localhost"  ),
  client_id: System.get_env( "CLOAK_MQTT_CLIENT",   "cloak_test" ),
  user_name: System.get_env( "CLOAK_MQTT_USERNAME", "cloak"      ),
  password:  System.get_env( "CLOAK_MQTT_PASSWORD", "cloak"      )
