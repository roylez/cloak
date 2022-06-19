require Logger

defmodule Cloak.Shadowsocks.TCPRelay do
  use    GenServer, shutdown: 2000
  import Cloak.Registry

  alias Cloak.Cipher

  defstruct ~w( account cipher )a

  @socket_opts   [ nodelay: true, keepalive: true, sndbuf: 2097152, recbuf: 2097152 ]
  @num_acceptors 5

  def start_link(account) do
    GenServer.start_link  __MODULE__, account, name: via({:tcp_relay, account.port})
  end

  def init(%{ port: port, method: method, passwd: passwd } = account) do
    # This makes it so that when your process "crashes", it calls the terminate/2
    # callback function prior to actually exiting the process. Using this method,
    # you can manually close your listening socket in the terminate function,
    # thereby avoiding the irritating port cleanup delay.
    Process.flag( :trap_exit , true )
    with { :ok, c } <- Cipher.setup(method, passwd),
         { :ok, _pid } <- _start_listener(port, c)
    do
      { :ok, %__MODULE__{ account: account, cipher: c } } 
    else
      { :error, reason }  -> { :stop, reason }
      _ -> :stop
    end
  end

  # cleanup listening socket
  def terminate(_, state) do
    _stop_listener(state.account.port)
    { :shutdown, state }
  end

  defp _start_listener(port, cipher) do
    :ranch.start_listener(
      {__MODULE__, port},
      :ranch_tcp,
      %{ num_acceptors: @num_acceptors, socket_opts: [port: port]++@socket_opts },
      _transmitter(cipher),
      %{ port: port, cipher: cipher }
    )
  end

  defp _stop_listener(port) do
    :ranch.stop_listener({__MODULE__, port})
  end

  def _transmitter(%{ category: :ss2022 }), do: Cloak.Shadowsocks.TCPTransmitter2022
  def _transmitter(_), do: Cloak.Shadowsocks.TCPTransmitter

end
