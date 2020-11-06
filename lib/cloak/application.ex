require Logger

defmodule Cloak.Application do
  use    Application

  def start(_type, _args) do

    children = [
      Cloak.Account,
      Cloak.DNSCache,
      Cloak.Bookkeeper,
      { Registry, keys: :unique, name: Cloak.Registry },
      { Common.TableManager, table_user: Cloak.Bookkeeper, table_name: :ledger },
      Cloak.Shadowsocks,
    ]

    mqtt   = if ( Application.get_env(:cloak, :enable_mqtt)   ) do [ Cloak.MQTT   ] else [] end
    static = if ( Application.get_env(:cloak, :enable_static) ) do [ Cloak.Static ] else [] end
    trojan = if ( Application.get_env(:cloak, :enable_trojan) ) do [ Cloak.Trojan ] else [] end

    children = children ++ mqtt ++ static ++ trojan

    Logger.info "Starting [ #{node()} ] node VERSION #{Application.spec(:cloak, :vsn)}"

    # See http://elixir-lang.org/docs/stable/elixir/Supervisor.html
    # for other strategies and supported options
    Supervisor.start_link(children, strategy: :one_for_one, name: Cloak)
  end

end
