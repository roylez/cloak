require Logger

defmodule Cloak.Shadowsocks.TCPTransmitter do
  use GenStateMachine, callback_mode: :state_functions
  @behaviour :ranch_protocol

  alias  Cloak.{ Conn, Cipher }

  defstruct(
    port:    nil,   # listening port
    cipher:  nil,   # cipher ctx
    local:   nil,   # client
    remote:  nil,   # target
    u:       0,     # upload size
    d:       0,     # download size
    error:   nil,   # errors
    request: nil    # initial request
  )

  def start_link(ref, :ranch_tcp, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [{ ref, opts }] )
    # pid = :proc_lib.spawn_opt(__MODULE__, :init, [{ ref, opts }], [:link, fullsweep_after: 0] )
    { :ok, pid }
  end

  def init({ ref, %{ cipher: c } = data }) do
    { :ok, l } = :ranch.handshake(ref)
    :inet.setopts(l, active: :once)
    { first_data, cipher } = Cipher.init_encoder(c)
    :gen_tcp.send(l, first_data)
    state = %{ local: l, cipher: cipher, port: data.port }
    :gen_statem.enter_loop( __MODULE__, [], :waiting, struct(__MODULE__, state))
  end

  def waiting(:info, {:tcp, l, d}, %{ local: l, remote: nil, cipher: c }=data) do
    :inet.setopts(l, active: :once)
    with { :ok, %{ iv: iv, data: payload } } <- Conn.split_package(d, c.iv_len),
         c <- Cipher.init_decoder(c, iv), 
         { :ok, c, res } <- Cipher.stream_decode(c, payload),
         { :ok, req } <- Conn.parse_shadowsocks_request(res)
    do
      { :next_state, :connecting, %{ data | cipher: c, request: req }, [{:next_event, :internal, :connect_remote }] }
    else
      { :error, x } -> { :stop, :normal, %{ data | error: x } }
    end
  end

  def waiting(:info, { :tcp_closed, _  }, _),     do: :stop
  def waiting(:info, { :tcp_error,  _, _  },  _), do: :stop

  def connecting(:internal, :connect_remote, %{ request: req }=data) do
    with { :ok, req } <- Conn.tcp_connect_remote(req),
         { :ok, req } <- Conn.tcp_send_request(req)
    do
      { :next_state, :connected, %{ data | remote: req.remote } }
    else
      { :error, x } -> { :stop, :normal, %{ data | error: x } }
    end
  end

  # local requests
  def connected(:info, {:tcp, l, req }, %{ local: l, remote: r, cipher: c} = data) do
    :inet.setopts(l, active: :once)
    with { :ok, c, req } <- Cipher.stream_decode(c, req) do
      u = data.u + byte_size(req)
      :gen_tcp.send(r, req)
      # Logger.debug "req: #{data.request.addr}, send: #{byte_size(req)}"
      { :keep_state, %{ data | cipher: c, u: u } }
    else
      { :error, x } -> { :stop, :normal, %{ data | error: x } }
    end
  end

  # remote responses
  def connected(:info, { :tcp, r, resp }, %{local: l, remote: r, cipher: c} = data) do
    :inet.setopts(r, active: :once)
    d = data.d + byte_size(resp)
    { :ok, c, resp } = Cipher.stream_encode(c, resp)
    :gen_tcp.send(l, resp)
    # Logger.debug "req: #{data.request.addr}, recv: #{byte_size(resp)}"
    { :keep_state, %{ data | cipher: c, d: d } }
  end

  def connected(:info, { :tcp_closed, _ }, data)  do
    # Logger.debug "tcp_closed, addr: #{data.request.addr}, u: #{data.u}, d: #{data.d}"
    Cloak.Bookkeeper.record_usage( data.port, data.u, data.d )
    :stop
  end

  def connected(:info, { :tcp_error, _from, _reason }, data)  do
    # Logger.debug "tcp_error, addr: #{data.request.addr}, u: #{data.u}, d: #{data.d}"
    Cloak.Bookkeeper.record_usage( data.port, data.u, data.d )
    :stop
  end

  def connected(:info, msg, data) do
    Logger.warn "Unhandled msg: #{inspect(msg)}"
    :inet.setopts(data.local, active: :once)
    :keep_state_and_data
  end

  def terminate(_, _, %{ error: error }=data) when not is_nil(error) do
    ip = Conn.port_ip(data.local)
    case error do
      :forged -> Logger.info  "[forged] #{inspect(ip)}:#{data.port}"
      reason  -> Logger.debug "[#{inspect(reason)}] #{inspect ip}:#{data.port}"
    end
  end

  def terminate(reason, state, data), do: super(reason, state, data)

end
