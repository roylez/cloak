require Logger

defmodule Cloak.Shadowsocks.Worker do
  use Supervisor
  import Cloak.Registry
  alias Cloak.{Shadowsocks, Cipher}

  def child_spec(account) do
    %{ 
      id: {__MODULE__, account.port}, 
      start: {__MODULE__, :start_link, [account]},
      type: :supervisor,
      restart: :transient
    }
  end

  def start_link(account) do
    Supervisor.start_link(__MODULE__, account, name: via({:worker, account.port}))
  end

  def init(%{ port: _port, method: m, passwd: _ } = account) do
    cipher_info = Cipher.parse_name(m) |> Cipher.info()
    children = case cipher_info do
      { :ss2022, _type, _algo, _kl, _ivl } -> 
        [ { Shadowsocks.TCPRelay, account }, { Shadowsocks.UDPRelay2022, account } ]
      _ -> 
        [ { Shadowsocks.TCPRelay, account }, { Shadowsocks.UDPRelay, account } ]
    end
    Supervisor.init(children, strategy: :one_for_one)
  end

end
