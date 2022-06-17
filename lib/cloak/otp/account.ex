require Logger

defmodule Cloak.Account do
  use Agent
  import Cloak.Registry
  alias Cloak.Shadowsocks
  @moduledoc """
  Module to manage ports used
  """

  @type ss_port() :: integer()
  @type t() :: %{
    port: ss_port(),
    method: String.t() | Cloak.Cipher.method(),
    passwd: String.t()
  }

  def start_link(_) do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  @doc """
  Starts a new port or reload a already start port. Takes a shadowsocks account definition map as input.

    add( %{ passwd: "11111", method: "chacha20", port: 9090 } )
  """
  @spec add( account :: t() ) :: :ok
  def add( %{ port: port, method: m, passwd: _ } = account ) when is_number(port) do
    case get(port) do
      nil ->
        case Shadowsocks.start_worker(account) do
          { :ok, _ } ->
            Logger.info "PORT #{port} started, cipher #{m}"
            Cloak.Trojan.reload()
            Agent.update(__MODULE__, &( Map.put( &1, port, account ) ))
          { :error, { :shutdown, reason } } ->
            Logger.warn "PORT #{port} start failed: #{inspect reason}"
            Logger.debug inspect(account)
          { :error, other } ->
            Logger.warn "PORT #{port} start failed: #{inspect other}"
            Logger.debug inspect(account)
        end
      ^account -> :ok
      _ ->
        Logger.info "PORT #{port}: reload - #{inspect account}"
        Shadowsocks.TCPRelay.set(port, account)
        Shadowsocks.UDPRelay.set(port, account)
        Cloak.Trojan.reload()
        Agent.update(__MODULE__, &( Map.put( &1, port, account ) ))
    end
  end
  def add( account ), do: Logger.warn "Invalid account: #{inspect account}"

  @doc """
  Removes an account by port.
  """
  @spec remove( port :: ss_port() ) :: :ok
  def remove( port ) do
    with %{ port: _ } <- get(port),
         pid when is_pid(pid) <- where({:worker, port})
    do
        Logger.info "PORT #{port}: stop"
        Shadowsocks.stop_worker( pid )
        Agent.update(__MODULE__, &( Map.delete(&1, port) ))
    else
      _ -> Agent.update(__MODULE__, &( Map.delete(&1, port) ))
    end
  end

  @doc """
  Returns the number of accounts that is serviced.
  """
  @spec count() :: integer()
  def count(), do: Agent.get(__MODULE__, &( map_size( &1 )))

  @doc """
  Returns all accounts that is serviced.
  """
  @spec all() :: map()
  def all(), do: Agent.get(__MODULE__, &( &1 ))

  @doc """
  Gets an account definition by port.
  """
  @spec get( port :: ss_port() ) :: nil | t()
  def get(port), do: Agent.get(__MODULE__, &( Map.get( &1, port ) ))

  @spec get( port :: ss_port(), pid :: boolean ) :: nil | map()
  def get(port, true) do
    case get(port) do
      nil -> nil
      acc ->
        Map.merge(acc, %{
          pid: where({:worker, port}),
          tcp: where({:tcp_relay, port}),
          udp: where({:udp_relay, port})
        })
    end
  end
  def get(port, false), do: get(port)

end

