require Logger

defmodule Cloak.Shadowsocks.TCPRelay do
  use    GenServer
  import Cloak.Registry

  alias Cloak.Cipher

  defstruct ~w( account listener cipher )a

  @socket_opts   [ nodelay: true, keepalive: true, sndbuf: 2097152, recbuf: 2097152 ]
  @num_acceptors 5

  def child_spec(args) do
    Supervisor.Spec.worker(__MODULE__, args, shutdown: 2000)
  end

  def start_link(account) do
    GenServer.start_link  __MODULE__, account, name: via({:tcp_relay, account.port})
  end

  def init(%{ port: port, method: method, passwd: passwd } = account) do
    # This makes it so that when your process "crashes", it calls the terminate/2
    # callback function prior to actually exiting the process. Using this method,
    # you can manually close your listening socket in the terminate function,
    # thereby avoiding the irritating port cleanup delay.
    Process.flag( :trap_exit , true )
    ref = { __MODULE__, port }
    with { :ok, c } <- Cipher.setup(method, passwd),
         { :ok, _pid } <- :ranch.start_listener(
           ref, :ranch_tcp,
           %{ num_acceptors: @num_acceptors, socket_opts: [port: port]++@socket_opts },
           Cloak.Shadowsocks.TCPTransmitter,
           %{ port: account.port, cipher: c })
    do
      { :ok, %__MODULE__{ listener: ref, account: account, cipher: c } } 
    else
      { :error, reason }  -> { :stop, reason }
      _ -> :stop
    end
  end

  # cleanup listening socket
  def terminate(_, state) do
    :ranch.stop_listener(state.listener)
    { :shutdown, state }
  end

  def handle_cast( { :set, %{ passwd: passwd, method: method } = account }, state ) do
    case Cipher.setup(method, passwd) do
      { :ok, c } ->
        :ranch.set_protocol_options(
          state.listener,
          %{ port: account.port, cipher: c })
        { :noreply, %{ state| account: account, cipher: c } }
      _ -> { :noreply, state }
    end
  end

  def set(pid, account) when is_pid(pid) do
    GenServer.cast(pid, { :set, account })
  end

  def set(port, account) when is_integer(port) do
    GenServer.cast(via({:tcp_relay, port}), { :set, account })
  end
end
