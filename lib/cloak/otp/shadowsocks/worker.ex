require Logger

defmodule Cloak.Shadowsocks.Worker do
  use Supervisor
  import Cloak.Registry
  alias Cloak.Shadowsocks

  def child_spec(account) do
    Supervisor.Spec.supervisor(__MODULE__, [account], restart: :transient)
  end

  def start_link(account) do
    Supervisor.start_link(__MODULE__, account, name: via({:worker, account.port}))
  end

  def init(%{ port: _port, method: _, passwd: _ } = account) do
    children = [ { Shadowsocks.TCPRelay, [account] }, { Shadowsocks.UDPRelay, [account] } ]

    Supervisor.init(children, strategy: :one_for_one)
  end

end
