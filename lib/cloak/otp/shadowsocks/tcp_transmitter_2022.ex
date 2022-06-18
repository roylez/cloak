require Logger

defmodule Cloak.Shadowsocks.TCPTransmitter2022 do
  use GenStateMachine
  @behaviour :ranch_protocol

  alias  Cloak.{ Conn, Cipher }

  defstruct [
    port:       nil, # listening port
    cipher:     nil, # cipher ctx
    local:      nil, # client
    local_ip:   nil, # client ip
    remote:     nil, # target
    u:          0,   # upload size
    d:          0,   # download size
    error:      nil, # errors
  ]

  def start_link(ref, :ranch_tcp, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [{ ref, opts }] )
    { :ok, pid }
  end

  def init({ ref, %{ cipher: c, port: port } }) do
    { :ok, l } = :ranch.handshake(ref)
    :inet.setopts(l, active: :once)
    data = %__MODULE__{ local: l, cipher: c, port: port, local_ip: Conn.port_ip(l) }
    Logger.metadata(port: port, client: inspect(data.local_ip))
    :gen_statem.enter_loop( __MODULE__, [], :waiting_client, data)
  end

  def handle_event(:info, {:tcp, l, d},
    :waiting_client,
    %{ local: l, remote: nil, cipher: c }=data)
  do
    :inet.setopts(l, active: :once)
    with { :ok, salt, <<fixed_header::binary-size(27), payload::binary>> } <- Conn.split_iv(d, c.iv_len),
         c <- Cipher.init_decoder(c, salt), 
         { :ok, c, <<0, timestamp::64, len::16>> } <- Cipher.decode(c, fixed_header),
         { :ok, c, res } <- Cipher.decode(c, payload),
         { :ok, req } <- Conn.parse_shadowsocks_request(res, true)
    do
      { :next_state, { :connecting_remote, req, salt } , %{ data | cipher: c }, [{:next_event, :internal, :connect_remote }] }
    else
      { :error, x } -> { :stop, :normal, %{ data | error: x } }
    end
  end

  def handle_event(:internal, :connect_remote, { :connecting_remote, req, _salt }, data) do
    with { :ok, req } <- Conn.tcp_connect_remote(req),
         { :ok, req } <- Conn.tcp_send_request(req)
    do
      { :keep_state, %{ data | remote: req.remote } }
    else
      { :error, x } -> { :stop, :normal, %{ data | error: x } }
    end
  end

  def handle_event(:info, { :tcp, r, resp }, {:connecting_remote, _req, client_salt}, %{local: l, remote: r, cipher: c} = data) do
    :inet.setopts(r, active: :once)
    { salt, c } = Cipher.init_encoder(c)
    timestamp = :os.system_time(:seconds)
    { :ok, c, header } = Cipher.encode(c, <<1, timestamp::64, client_salt::bytes, byte_size(resp)::16>>)
    { :ok, c, resp   } = Cipher.encode(c, resp)
    :gen_tcp.send(l, salt <> header <> resp)
    { :next_state, :connected, %{ data | cipher: c } }
  end

  # local requests
  def handle_event(:info, {:tcp, l, req }, :connected, %{ local: l, remote: r, cipher: c} = data) do
    :inet.setopts(l, active: :once)
    with { :ok, c, req } <- Cipher.stream_decode(c, req) do
      u = data.u + byte_size(req)
      :gen_tcp.send(r, req)
      { :keep_state, %{ data | cipher: c, u: u } }
    else
      { :error, x } -> { :stop, :normal, %{ data | error: x } }
    end
  end

  # remote responses
  def handle_event(:info, { :tcp, r, resp }, :connected, %{local: l, remote: r, cipher: c} = data) do
    :inet.setopts(r, active: :once)
    d = data.d + byte_size(resp)
    { :ok, c, resp } = Cipher.stream_encode(c, resp)
    :gen_tcp.send(l, resp)
    { :keep_state, %{ data | cipher: c, d: d } }
  end

  def handle_event(:info, { :tcp_closed, _ }, _, data)  do
    Cloak.Bookkeeper.record_usage( data.port, data.u, data.d )
    :stop
  end

  def handle_event(:info, { :tcp_error, _from, _reason }, _, data)  do
    Cloak.Bookkeeper.record_usage( data.port, data.u, data.d )
    :stop
  end

  def connected(:info, msg, data) do
    Logger.warn "Unhandled msg: #{inspect(msg)}"
    :inet.setopts(data.local, active: :once)
    :keep_state_and_data
  end

  def terminate(_, _, %{ error: error }=data) when not is_nil(error) do
    case error do
      :forged -> Logger.info  "[forged] #{inspect(data.local_ip)}"
      reason  -> Logger.debug "[#{inspect(reason)}] #{inspect(data.local_ip)}"
    end
  end

  def terminate(reason, state, data), do: super(reason, state, data)

end
