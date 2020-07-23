defmodule Cloak do
  alias Cloak.Account
  @moduledoc """
  A shadowsocks server implemented in Elixir.

  Due to availability of crypto library choices, only one openssl based cipher aes-128-cfb is implemented,
  but all libsodium based ciphers are supported using libsalty NIF.
  """
  defdelegate start(acc), to: Account,    as: :add
  defdelegate stop(port), to: Account,    as: :remove
  defdelegate get(port),  to: Account,    as: :get
  defdelegate list(),     to: __MODULE__, as: :accounts

  @doc """
  returns a map of accounts using port number as key, also showing running
  process ID of tcp and udp relay processes.

  """
  @spec accounts(  ) :: map
  def accounts do
    Account.all()
    |> Stream.map(fn {pt, h} ->
      { pt,
        Map.merge(h, %{
          tcp: Cloak.Registry.where({:tcp_relay, pt}),
          udp: Cloak.Registry.where({:udp_relay, pt}) })
      }
    end)
    |> Enum.into(%{})
  end
end
