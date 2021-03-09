require Logger

defmodule Cloak.Trojan do
  use GenServer, shutdown: 2000
  alias Cloak.Account

  @socket_opts   [ nodelay: true, keepalive: true, sndbuf: 2097152, recbuf: 2097152 ]

  defstruct  ~w( listener transmitter_opts )a

  def start_link(_) do
    GenServer.start_link(__MODULE__, nil, name: __MODULE__)
  end

  def init(_) do
    Process.flag( :trap_exit, true )
    ref = { :trojan, __MODULE__ }
    opts = Application.get_env(:cloak, :trojan)
    { server,      opts } = Keyword.pop(opts, :fake_server)
    { server_port, opts } = Keyword.pop(opts, :fake_server_port)

    transmitter_opts = %{ server: { server, server_port }, password_hash: _password_hash() }

    case :ranch.start_listener(
      ref, :ranch_ssl, 
      %{ socket_opts: opts ++ @socket_opts },
      Cloak.Trojan.Transmitter, transmitter_opts) do
      { :ok, _pid } ->
        Logger.info "Starting trojan at port 2000"
        { :ok, %__MODULE__{ listener: ref, transmitter_opts: transmitter_opts } }
      { :error, reason } ->
        Logger.info "Failed to start trojan, #{inspect reason}"
        { :stop, reason }
      _ -> :stop
    end
  end

  def handle_cast(:reload, %{ transmitter_opts: opts }=state) do
    opts = Map.put(opts, :password_hash, _password_hash())
    :ranch.set_protocol_options(state.listener, opts)
    { :noreply, %{ state | transmitter_opts: opts } }
  end

  def reload() do
    GenServer.cast(__MODULE__, :reload)
  end

  def terminate(_, state) do
    :ranch.stop_listener(state.listener)
    { :shutdown, state }
  end

  defp _password_hash() do
    Account.all()
    |> Enum.map(fn {port, acc} ->
      { _sha224_hash("#{port}.#{acc.passwd}"), port } end)
    |> Enum.into(%{})
  end

  defp _sha224_hash(str) do
    :crypto.hash(:sha224, str)
    |> Base.encode16(case: :lower)
  end
end
