require Logger

defmodule Cloak.Static do
  use GenServer

  @config_file     "/etc/cloak.yml"
  @reload_interval 120_000

  alias Cloak.Account

  def init( _ ) do
    accounts = _load_accounts()
    Logger.info "Loaded #{length(accounts)} static accounts"
    Enum.map(accounts, &Account.add/1)
    Process.send_after(self(), :reload, @reload_interval)
    { :ok, accounts }
  end

  def start_link(_) do
    GenServer.start_link(__MODULE__, nil, name: __MODULE__, hibernate_after: 3_000)
  end

  def handle_info(:reload, accounts) do
    new = _load_accounts()
    if new != accounts do
      Logger.info "STATIC ACCOUNTS CHANGED"
      new
      |> Enum.map( &Account.add/1 )
      accounts
      |> Enum.reject( fn x -> Enum.any?(new, &(&1.port == x.port)) end)
      |> Enum.map( &( Account.remove(&1.port) ) )
    end
    Process.send_after(self(), :reload, @reload_interval)
    { :noreply, new }
  end

  defp _santize_account(acc) do
    acc
    |> Enum.map( fn {k, v} -> {String.to_atom(k), v} end )
    |> Enum.into( %{} )
    |> Map.take(~w( port passwd method )a)
    |> Map.update(:passwd, "passwd", &to_string/1)
  end

  defp _load_accounts(conf \\ @config_file) do
    case YamlElixir.read_from_file( conf, atoms: true ) do
      { :ok, accounts } ->
        accounts
        |> Enum.map(&_santize_account/1)
      _ -> []
    end
  end
end
