require Logger

defmodule Cloak.Trojan.Transmitter do
  use GenStateMachine, callback_mode: :state_functions
  @behaviour :ranch_protocol
  alias Cloak.{ Conn, Bookkeeper }

  @udp_socket_option [:binary, active: :once, reuseaddr: true ]
  @transport :ranch_ssl
  defstruct(
    local:         nil, # client
    remote:        nil, # target
    port:          nil, # account port, initialized when verified
    u:             0,   # upload size
    d:             0,   # download size
    error:         nil, # errors
    request:       nil, # initial request
    password_hash: %{}, # hashed "<port>.<passwd>" strings
    server:        nil  # upstream server to redirect to when is not valid trojan traffic
  )

  def start_link(ref, :ranch_ssl, opts) do
    pid = :proc_lib.spawn_link(__MODULE__, :init, [{ref, opts}])
    { :ok, pid }
  end

  def init({ref, %{ server: server, password_hash: password_hash }}) do
    { :ok, socket } = :ranch.handshake(ref)
    @transport.setopts(socket, active: :once)
    :gen_statem.enter_loop(__MODULE__, [], :waiting,
      %__MODULE__{
        local: socket,
        password_hash: password_hash,
        server: server
      })
  end

  # Initial verification. << 13, 10 >> is CRLF
  def waiting(:info, 
    { :ssl, _ssl_socket, <<str::bytes-56, 13, 10, rest::bytes>> },
    %{ password_hash: hash }=data 
  ) when is_map_key(hash, str) do
    @transport.setopts(data.local, active: :once)
    with { :ok, req } <- Conn.parse_trojan_request(rest) do
      { 
        :next_state,
        :"#{req.protocol}_connecting",
        %{ data | request: req, port: Map.get(hash, str) },
        [{:next_event, :internal, :connect_remote }]
      }
    else
      { :error, x } -> 
        Logger.debug "Error: #{inspect x}"
        { :stop, :normal, %{ data | error: x } }
    end
  end

  def waiting(:info,
    { :ssl, _ssl_socket, "GET /" <> _=payload },
    data) do
    @transport.setopts(data.local, active: :once)
    { addr, port } = data.server
    req = %{ protocol: :udp, req_type: 3, addr: addr, port: port, payload: payload }
    { :ok, req } = Conn.resolve_remote_address(req)
    { 
      :next_state,
      :fake_connecting,
      %{ data | request: req },
      [{:next_event, :internal, :connect_remote }]
    }
  end

  def waiting(:info, { :ssl_closed, _  }, _),     do: :stop
  def waiting(:info, { :ssl_error,  _, _  },  _), do: :stop

  def waiting(:info, msg, data) do
    Logger.debug inspect(data)
    Logger.debug inspect(msg)
    :stop
  end

  def tcp_connecting(:internal, :connect_remote, %{ request: req }=data) do
    with { :ok, req } <- Conn.tcp_connect_remote(req) do
      {
        :next_state,
        :tcp_connected,
        %{ data | remote: req.remote },
        [{:next_event, :info, {:ssl, nil, req.payload}}]
      }
    else
      { :error, x } -> { :stop, :normal, %{ data | error: x } }
    end
  end

  def udp_connecting(:internal, :connect_remote, %{ request: req }=data) do
    { :ok, client } = :gen_udp.open(0, @udp_socket_option)
    {
      :next_state,
      :udp_connected,
      %{ data | remote: client },
      [{:next_event, :info, {:ssl, nil, req.payload}}]
    }
  end

  def fake_connecting(:internal, :connect_remote, %{ request: req }=data) do
    with { :ok, req } <- Conn.tcp_connect_remote(req) do
      {
        :next_state,
        :faking,
        %{ data | remote: req.remote },
        [{:next_event, :info, {:ssl, nil, req.payload}}]
      }
    else
      { :error, x } -> { :stop, :normal, %{ data | error: x } }
    end
  end

  # TCP local requests
  def faking(:info, {:ssl, _, req }, %{ local: l, remote: r }) do
    @transport.setopts(l, active: :once)
    :gen_tcp.send(r, req)
    :keep_state_and_data
  end

  # TCP remote responses
  def faking(:info, { :tcp, r, resp }, %{local: l, remote: r}) do
    :inet.setopts(r, active: :once)
    @transport.send(l, resp)
    :keep_state_and_data
  end
  def faking(:info, _, _data), do: :stop

  # TCP local requests
  def tcp_connected(:info, {:ssl, _, req }, %{ local: l, remote: r }=data) do
    @transport.setopts(l, active: :once)
    u = data.u + byte_size(req)
    :gen_tcp.send(r, req)
    { :keep_state, %{ data | u: u } }
  end

  # TCP remote responses
  def tcp_connected(:info, { :tcp, r, resp }, %{local: l, remote: r}=data) do
    :inet.setopts(r, active: :once)
    d = data.d + byte_size(resp)
    @transport.send(l, resp)
    { :keep_state, %{ data | d: d } }
  end

  def tcp_connected(:info, { closed, _  }, data) when closed in [:ssl_closed, :tcp_closed]  do
    Bookkeeper.record_usage( data.port, data.u, data.d )
    :stop
  end

  def tcp_connected(:info, { error, _, _  }, data) when error in [:ssl_error, :tcp_error]  do
    Bookkeeper.record_usage( data.port, data.u, data.d )
    :stop
  end

  # UDP local requests
  def udp_connected(:info, {:ssl, _, payload }, %{ local: l, remote: r }=data) do
    @transport.setopts(l, active: :once)
    u = data.u + byte_size(payload)
    { :ok, req } = Conn.parse_trojan_udp_packet(payload)
    Conn.udp_send(r, req)
    { :keep_state, %{ data | u: u } }
  end

  # UDP remote responses
  def udp_connected(:info, { :udp, _, from, from_pt, payload }, %{local: l, remote: r}=data) do
    :inet.setopts(r, active: :once)
    resp = <<1>> <> Enum.join(Tuple.to_list(from)) <> << from_pt::size(16), byte_size(payload)::size(16), 13, 10, payload::bytes >>
    d = data.d + byte_size(resp)
    @transport.send(l, resp)
    { :keep_state, %{ data | d: d } }
  end

  def udp_connected(:info, { closed, _  }, data) when closed in [:ssl_closed, :udp_closed]  do
    Bookkeeper.record_usage( data.port, data.u, data.d )
    :stop
  end

  def udp_connected(:info, { :ssl_error, _, _  }, data) do
    Bookkeeper.record_usage( data.port, data.u, data.d )
    :stop
  end

end
