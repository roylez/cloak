require Logger

defmodule Cloak.Conn do
  @socket_option [
    :binary,
    active:    :once,
    nodelay:   true,
    keepalive: true,
    packet:    0,
    sndbuf:    2097152,
    recbuf:    2097152,
    reuseaddr: true ]

  @tcp_retry  2  # how many times will each remote be tried?

  alias Cloak.DNSCache

  def split_package( data, iv_size ) when byte_size(data) > iv_size do
    <<iv::bytes-size(iv_size), payload::bytes>>  = data
    { :ok, %{ iv: iv, data: payload } }
  end

  def split_package( _, _), do: { :error, :invalid_request }

  @doc """
  parse a request according to shadowsocks or trojan protocol
  """
  @spec parse_shadowsocks_request( data :: binary ) :: { :ok, map } | { :error, :invalid_request }
  def parse_shadowsocks_request( data ) when is_binary(data) do
    res = case data do
      # IPV4: TYPE(1) IP(4) PORT(2) PAYLOAD
      <<1, addr::bytes-4, port::16, payload::bytes>> ->
        { :ok, %{ req_type: 1, addr: addr, port: port, payload: payload } }
      # FQDN(type=3): TYPE(1) LEN(1) ADDR(LEN) PORT(2) PAYLOAD
      <<3, len, addr::bytes-size(len), port::16, payload::bytes >> ->
        { :ok, %{ req_type: 3, addr: addr, port: port, payload: payload } }
      # IPV6(type=4): TYPE(1) ADDR(16) PORT(2) PAYLOAD
      <<4, addr::bytes-16, port::16, payload::bytes>> ->
        { :ok, %{ req_type: 4, addr: addr, port: port, payload: payload } }
      _ ->
        { :error, :invalid_request }
    end
    with { :ok, req } <- res,
         { :ok, req } <- resolve_remote_address(req),
         { :ok, req } <- _filter_forbidden_addresses(req) do
      { :ok, req }
    end
  end

  @spec parse_shadowsocks_request( data :: map ) :: { :ok, map } | { :error, :invalid_request }
  def parse_shadowsocks_request( %{ data: data }=req ) do
    with { :ok, res } <- parse_shadowsocks_request(data), do: { :ok, Map.merge(req, res) }
  end

  @spec parse_trojan_request( data :: binary ) :: { :ok, map } | { :error, :invalid_request }
  def parse_trojan_request(data) do
    res = case data do
      # TCP
      <<1, 1, addr::bytes-4, port::16, 13, 10, payload::bytes>> ->
        { :ok, %{ protocol: :tcp, req_type: 1, addr: addr, port: port, payload: payload }}
      <<1, 3, len, addr::bytes-size(len), port::16, 13, 10, payload::bytes>> ->
        { :ok, %{ protocol: :tcp, req_type: 3, addr: addr, port: port, payload: payload }}
      <<1, 4, addr::bytes-16, port::16, 13, 10, payload::bytes>> ->
        { :ok, %{ protocol: :tcp, req_type: 4, addr: addr, port: port, payload: payload }}
      # UDP inital
      <<3, 1, addr::bytes-4, port::16, 13, 10, payload::bytes>> ->
        { :ok, %{ protocol: :udp, req_type: 1, addr: addr, port: port, payload: payload }}
      <<3, 3, len, addr::bytes-size(len), port::16, 13, 10, payload::bytes>> ->
        { :ok, %{ protocol: :udp, req_type: 3, addr: addr, port: port, payload: payload }}
      <<3, 4, addr::bytes-16, port::16, 13, 10, payload::bytes>> ->
        { :ok, %{ protocol: :udp, req_type: 4, addr: addr, port: port, payload: payload }}
      _ ->
        { :error, :invalid_request }
    end
    with { :ok, req } <- res,
         { :ok, req } <- resolve_remote_address(req),
         { :ok, req } <- _filter_forbidden_addresses(req) do
      { :ok, req }
    end
  end

  @spec parse_trojan_udp_packet( data :: binary ) :: { :ok, map } | { :error, :invalid_request }
  def parse_trojan_udp_packet(data) do
    res = case data do
      <<1, addr::bytes-4, port::16, _l::16, 13, 10, payload::bytes>> ->
        { :ok, %{ protocol: :udp, req_type: 1, addr: addr, port: port, payload: payload }}
      <<3, len, addr::bytes-size(len), port::16, _l::16, 13, 10, payload::bytes>> ->
        { :ok, %{ protocol: :udp, req_type: 3, addr: addr, port: port, payload: payload }}
      <<4, addr::bytes-16, port::16, _l::16, 13, 10, payload::bytes>> ->
        { :ok, %{ protocol: :udp, req_type: 4, addr: addr, port: port, payload: payload }}
      _ ->
        { :error, :invalid_request }
    end
    with { :ok, req } <- res,
         { :ok, req } <- resolve_remote_address(req),
         { :ok, req } <- _filter_forbidden_addresses(req) do
      { :ok, req }
    end
  end

  @doc """
  Make a UDP package
  """
  @spec udp_build_packet( data :: binary, ip :: tuple, port :: integer ) :: binary
  def udp_build_packet( payload, {a,b,c,d}, port), do: <<1, a, b, c, d, port::size(16), payload::binary>>

  # host name requests
  def resolve_remote_address(%{req_type: 3, addr: addr } = req) do
    # addr can be a string of IP or hostname, both can be handled by
    # :inet.getaddr/2
    # In case addr is random nonsense, an Exception is raised by :to_charlist/1
    try do
      if ip = DNSCache.get(addr) do
        { :ok, Map.put(req, :ip, ip) }
      else
        addr_cl = to_charlist(addr)
        case :inet.getaddr(addr_cl, :inet) do
          { :ok,    ip } ->
            DNSCache.set(addr, ip)
            { :ok, Map.put(req, :ip, ip ) }
          { :error, _  } -> { :error, { :nxdomain, addr } }
        end
      end
    rescue
      _ -> { :error, :invalid_request }
    end
  end

  # IPV4 requests
  def resolve_remote_address(%{req_type: 1, addr: addr} = req) do
    ip = addr
         |> :binary.bin_to_list
         |> List.to_tuple
    { :ok, Map.put(req, :ip, ip ) }
  end

  # IPV6 requests
  def resolve_remote_address(%{req_type: 4, addr: addr} = req) do
    ip = for <<group::16 <- addr>> do group end
         |> List.to_tuple()     # { x, x, x, x, x, x, x, x } representation
         |> :inet.ntoa()        # ::xx:xx:xx representation, :gen_tcp.connect only takes this one
    { :ok, Map.put(req, :ip, ip ) }
  end
  def resolve_remote_address(_), do: { :error, :invalid_request }

  if Mix.env == :prod do
    defp _filter_forbidden_addresses( %{ ip: ip }=req ) do
      case ip do
        { 192, 168, _, _ } -> { :error, :private_address }
        { 10,  _,   _, _ } -> { :error, :private_address }
        { 127, 0,   0, _ } -> { :error, :private_address }
        { 0,   _,   _, _ } -> { :error, :private_address }
        { 172, x,   _, _ } when x in 16..31 -> { :error, :private_address }
        _ -> { :ok, req }
      end
    end
  else
    defp _filter_forbidden_addresses( req ), do: { :ok, req }
  end 

  def tcp_send_request(%{ remote: r, payload: payload }=req) when byte_size(payload) > 0 do
    case :gen_tcp.send(r, payload) do
      :ok -> { :ok, req }
      { :error, _ } -> { :error, :invalid_conn }
    end
  end
  def tcp_send_request(%{ payload: payload }=req) when byte_size(payload) == 0, do: { :ok, req }
  def tcp_send_request(_), do: { :error, :invalid_conn }

  def tcp_connect_remote(req), do: tcp_connect_remote(req, @socket_option, @tcp_retry)
  def tcp_connect_remote(%{ ip: r, port: port }=req, opts, retry) when retry > 1 do
    case :gen_tcp.connect(r, port, opts) do
      { :ok, client }  ->
        { :ok, req |> Map.put(:remote, client) }
      { :error, _   }  ->
        Logger.debug "retrying! #{inspect r}:#{port}"
        :timer.sleep(10)
        tcp_connect_remote(req, port, opts, retry - 1)
    end
  end

  def tcp_connect_remote(%{ ip: r, port: port }=req, port, opts, 1 ) do
    case :gen_tcp.connect(r, port, opts) do
      { :ok,    client }  ->
        { :ok, req |> Map.put(:remote, client) }
      { :error, reason }  ->
        Logger.debug "Error connecting to #{inspect req.addr}:#{port} :: #{reason}"
        { :error, reason }
    end
  end

  def udp_send(client, %{ ip: ip, port: port, payload: payload} = req) do
    :gen_udp.send(client, ip, port, payload)
    { :ok, Map.put(req, :remote, client) }
  end

  def udp_send(%{ ip: ip, port: port, payload: payload} = req) do
    { :ok, client } = :gen_udp.open(0, [:binary, reuseaddr: true])
    :gen_udp.send(client, ip, port, payload)
    { :ok, Map.put(req, :remote, client) }
  end

  def port_ip(port) do
    case :inet.peername(port) do
      { :ok, { ip, _ } } -> ip
      { :error, _ } -> nil
    end
  end
end

