require Logger

defmodule Cloak.Shadowsocks.UDPRelay2022 do
  use    GenServer, shutdown: 2000
  import Cloak.Registry
  alias  Cloak.{ Cipher, Conn }

  @socket_option [:binary, active: :once, reuseaddr: true ]
  @port_ttl      10

  defstruct(
    account:      nil,
    port:         nil,
    cipher:       nil,
    req_ports:    %{},
    block_cipher: nil,
  )

  def start_link(account) do
    GenServer.start_link(
      __MODULE__,
      account,
      name: via({:udp_relay, account.port}),
      spawn_opt: [fullsweep_after: 0]
    )
  end

  def init(%{ port: port, method: method, passwd: passwd } = account) do
    # This makes it so that when your process "crashes", it calls the terminate/2
    # callback function prior to actually exiting the process. Using this method,
    # you can manually close your listening socket in the terminate function,
    # thereby avoiding the irritating port cleanup delay.
    Process.flag( :trap_exit , true )
    with { :ok, pt } <- :gen_udp.open(port, @socket_option),
         { :ok, c } <- Cipher.setup(method, passwd)
    do
      # do not start timer at the sametime for all processes
      Process.send_after(self(), :ttl, Enum.random(1..(@port_ttl * 1000)))
      { :ok, %__MODULE__{ port: pt, account: account, cipher: c } }
    else
      { :error, reason }  -> { :stop, reason }
      _ -> :stop
    end
  end

  # request to udp servicing port
  def handle_info({ :udp, pt, ip, rport, payload }, %{ port: pt, cipher: c } = state ) do
    :inet.setopts(pt, active: :once)
    with <<header::bytes-16, body::bytes>> <- payload,
         <<session_id::bytes-8, _packet_id::64>>=decrypted_header <- _decrypt_header(c, header),
         <<_::bytes-4, nonce::little-96>> = decrypted_header,
         %{ decoder: { subkey, _ } } <- Cipher.init_decoder(c, session_id),
         c = %{ c | decoder: { subkey, nonce } },
         { :ok, _, decoded } <- Cipher.decode(c, body),
         <<0, timestamp::64, pad_len::16, _::bytes-size(pad_len), request_data::bytes>> <- decoded,
         { :ok, req } <- Conn.parse_shadowsocks_request(request_data), 
         { :ok, req } <- Conn.udp_send(req)
    do
      req_ports = Map.put(state.req_ports, req.remote, { ip, rport, session_id, :os.system_time(:seconds) + @port_ttl })
      { :noreply, %{ state | req_ports: req_ports } }
    else
      { :error, reason } when reason in ~w( invalid_request private_address )a -> { :noreply, state }
      { :error, reason } when is_atom(reason) ->
        Logger.warn "#{reason} / udp:#{state.account.port} / #{inspect ip}"
        { :noreply, state }
      { :error, { :nxdomain, req } } ->
        Logger.debug "UDP [nxdomain]: #{inspect(req)}"
        { :noreply, state }
      { :error, { reason, req } } ->
        Logger.warn "----- Unhandled UDP connection: #{inspect(reason)} -----"
        Logger.warn "request: #{inspect(req)}"
        { :noreply, state }
      e -> { :noreply, state }
    end
  end

  # received response from remote
  def handle_info( { :udp, pt, addr, _port, payload }, %{ req_ports: req_ports, cipher: c } = state ) do
    :inet.setopts(pt, active: :once)
    with { ip, port, client_session_id, _expiry } <- req_ports[pt],
         { session_id, %{ encoder: { subkey, _ } } } <- Cipher.init_encoder(c, 8)
    do
      d = _build_packet(payload, addr, port, client_session_id)
      <<_::bytes-4, nonce::little-96>>=header = <<session_id::bytes-8, 1::64>>
      encrypted_header = _encrypt_header(c, header)
      c = %{ c | encoder: { subkey, nonce } }
      { :ok, _, encoded } = Cipher.encode(c, d)
      :gen_udp.send(state.port, ip, port, encrypted_header <> encoded)
      req_ports = Map.put(req_ports, pt, { ip, port, client_session_id, :os.system_time(:seconds) + @port_ttl })
      { :noreply, %{ state | req_ports: req_ports }}
    else
      _ -> { :noreply, state }
    end
  end

  def handle_info( { :udp_closed, pt }, %{ port: port, req_ports: req_ports } = state) when pt != port do
    req_ports = Map.delete(req_ports, pt)
    :gen_udp.close( pt )
    { :noreply, %{ state | req_ports: req_ports } }
  end

  # remove unused ports after @port_ttl seconds of inactivity
  def handle_info(:ttl, %{ req_ports: req_ports } = state ) do
    now = :os.system_time(:seconds)
    req_ports
    |> Enum.filter( fn {_, {_, _, _, exp }} -> exp < now end )
    |> Enum.map(fn {pt, _} -> :gen_udp.close(pt) end )
    req_ports = req_ports
                |> Enum.reject(fn {_, {_, _, _, exp}} -> exp < now end)
                |> Enum.into(%{})
    Process.send_after(self(), :ttl, @port_ttl * 1000)
    { :noreply, %{ state | req_ports: req_ports }}
  end

  # handle all
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # cleanup listening socket
  def terminate(_, state), do: { :shutdown, state }

  defp _encrypt_header(cipher, data) do
    case cipher.method do
      :blake3_aes_128_gcm -> :crypto.crypto_one_time(:aes_128_ecb, cipher.key, data, true)
      :blake3_aes_256_gcm -> :crypto.crypto_one_time(:aes_256_ecb, cipher.key, data, true)
    end
  end

  defp _decrypt_header(cipher, data) do
    case cipher.method do
      :blake3_aes_128_gcm -> :crypto.crypto_one_time(:aes_128_ecb, cipher.key, data, false)
      :blake3_aes_256_gcm -> :crypto.crypto_one_time(:aes_256_ecb, cipher.key, data, false)
    end
  end

  # server to client header
  # +------+---------------+-------------------+----------------+----------+------+----------+-------+
  # | type |   timestamp   | client session ID | padding length |  padding | ATYP |  address |  port |
  # +------+---------------+-------------------+----------------+----------+------+----------+-------+
  # |  1B  | 8B unix epoch |         8B        |     u16be      | variable |  1B  | variable | u16be |
  # +------+---------------+-------------------+----------------+----------+------+----------+-------+
  defp _build_packet( payload, {a,b,c,d}, port, client_session_id) do
    time = :os.system_time(:seconds)
    pad_len = :rand.uniform(900)
    pad = :crypto.strong_rand_bytes(pad_len)
    <<1, time::64, client_session_id::bytes, pad_len::16, pad::bytes, 1, a, b, c, d, port::16, payload::bytes>>
  end

end

