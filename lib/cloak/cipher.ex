defmodule Cloak.Cipher do
  @moduledoc """
  Crypto related functions
  """

  @type method :: atom()
  @type ctx :: tuple()
  @type t :: %__MODULE__{}

  alias __MODULE__

  defstruct [
    method:  nil,   # encryption method
    key:     nil,   # derived key or aead master key
    # encoding context
    #   cfb and ctr ciphers:  erl crypto state reference
    #   stream ciphers:       { key, iv, counter }
    #   AEAD:                 { subkey, nonce, tag }
    #   2022-blake3:          { subkey, nonce }
    encoder: nil,
    decoder: nil,
    key_len: 0,    # key size
    iv_len: 0,     # iv size
    type: :stream,  # cipher type, aead / stream / block
  ]

  @ciphers %{
    aes_128_ctr:            { 16, 16, :ctr },
    aes_192_ctr:            { 24, 16, :ctr },
    aes_256_ctr:            { 32, 16, :ctr },
    aes_128_cfb:            { 16, 16, :block  },
    aes_192_cfb:            { 24, 16, :block  },
    aes_256_cfb:            { 32, 16, :block  },
    # { key, iv, cipher_type } size pair for streaming ciphers
    chacha20:               { 32, 8,  :stream },
    chacha20_ietf:          { 32, 12, :stream },
    salsa20:                { 32, 8,  :stream },
    # { key, salt } size pair for AEAD ciphers
    aes_256_gcm:             { 32, 32, :aead },
    chacha20_ietf_poly1305:  { 32, 32, :aead },
    xchacha20_ietf_poly1305: { 32, 32, :aead },
    # { key, salt } size pair for 2022_blake3 ciphers
    blake3_aes_256_gcm:      { 32, 32, :ss2022 },
  }
  @sodium_block_size 64
  @sodium_aead %{ 
    aes_256_gcm:             Salty.Aead.Aes256gcm,
    blake3_aes_256_gcm:      Salty.Aead.Aes256gcm,
    chacha20_ietf_poly1305:  Salty.Aead.Chacha20poly1305Ietf,
    xchacha20_ietf_poly1305: Salty.Aead.Xchacha20poly1305Ietf
  }
  @sodium_stream %{
    chacha20:      Salty.Stream.Chacha20,
    salsa20:       Salty.Stream.Salsa20,
    chacha20_ietf: Salty.Stream.Chacha20Ietf
  }

  @doc """
  computes key or masterkey
  """
  @spec setup(atom | String.t, passwd::String.t ) :: { :ok, t } | { :error, :invalid_method }
  def setup(method, passwd) when is_binary(method) do
    method |> parse_name() |> setup(passwd)
  end
  def setup(method, _passwd) when not is_map_key(@ciphers, method), do: { :error, :invalid_method }
  def setup(method, passwd) do
    { key_len, iv_len, type } = @ciphers[method]
    res = %__MODULE__{ method: method, key_len: key_len, iv_len: iv_len, type: type }
    if type == :ss2022 do
      with {:ok, key} <- Base.decode64(passwd),
           ^key_len <- byte_size(key)
      do
        { :ok, %{ res | key: key } }
      else
        e when is_integer(e) -> { :error, :invalid_passwd_length }
        _ -> { :error, :invalid_method }
      end
    else
      { :ok, %{ res | key: compute_key(passwd, key_len, iv_len) } }
    end
  end

  @spec stream_encode( t, data::binary ) :: { :ok, t, res::binary }
  def stream_encode(%Cipher{}=c, ""), do: { :ok, c, "" }
  def stream_encode(%Cipher{ type: :aead }=c, data) when byte_size(data) > 0x3FFF do
    { :ok, c , res }  = stream_encode(c, binary_part(data, 0, 0x3FFF))
    { :ok, c , more } = stream_encode(c, binary_part(data, 0x3FFF, byte_size(data)-0x3FFF))
    { :ok, c , res <> more }
  end
  def stream_encode(%Cipher{ type: :ss2022 }=c, data) when byte_size(data) > 0xFFFF do
    { :ok, c , res }  = stream_encode(c, binary_part(data, 0, 0xFFFF))
    { :ok, c , more } = stream_encode(c, binary_part(data, 0xFFFF, byte_size(data)-0xFFFF))
    { :ok, c , res <> more }
  end
  def stream_encode(%Cipher{ type: type }=c, data)
  when type in [:aead, :ss2022] do
    l = byte_size(data)
    { :ok, c, len } = encode(c, << l::16 >>)
    { :ok, c, res } = encode(c, data)
    { :ok, c, len <> res }
  end
  def stream_encode(%Cipher{}=c, data), do: encode(c, data)
  
  @spec stream_decode( t, data::binary ) :: { :ok, t, res::binary }

  def stream_decode(%Cipher{}=c, ""), do: { :ok, c, "" }
  def stream_decode(%Cipher{type: type, decoder: {key, nonce, buf}}=c, data) when type in [:aead, :ss2022] do
    stream_decode(%{c|decoder: {key, nonce}}, buf<>data)
  end
  def stream_decode(%Cipher{type: type}=c, <<len::bytes-18, rest::bytes>>=data) when type in [:aead, :ss2022] do
    case decode(c, len) do
      # not enough data for a full package decode, leave it for next time
      { :ok, _, <<len::16>> } when (len+16) > byte_size(rest) ->
        { key, nonce } = c.decoder
        { :ok, %{ c| decoder: { key, nonce, data }}, "" }
      { :ok, c, <<len::16>> } ->
        datalen = len+16
        case rest do
          << payload::bytes-size(datalen) >> ->
            with { :ok, c, res } <- decode(c, payload), do: { :ok, c, res }
          << payload::bytes-size(datalen), next::bytes >> ->
            with { :ok, c, res }  <- decode(c, payload),
                 { :ok, c, more } <- stream_decode(c, next), do: { :ok, c, res <> more }
        end
      # error decoding length
      { :error, reason } -> { :error, reason }
    end
  end
  # when there is not enough data for decoding
  def stream_decode(%Cipher{type: type, decoder: { key, nonce} }=c, data) when type in [:aead, :ss2022] do
    { :ok, %{ c| decoder: { key, nonce, data } }, "" }
  end
  def stream_decode(%Cipher{}=c, data), do: decode(c, data)

  @spec init_encoder( t ) :: { iv::binary, t }
  def init_encoder(%{ iv_len: len }=c), do: init_encoder(c, len)

  @spec init_encoder( t, integer ) :: { iv::binary, t }
  def init_encoder(c, len) when is_integer(len), do: init_encoder(c, _generate_iv(len))

  @spec init_encoder( t, binary ) :: { iv::binary, t }
  def init_encoder(%{ type: type, key: key }=c, salt)
  when type in [:aead, :ss2022] do
    subkey = compute_subkey(type, key, salt)
    { salt, %{ c | encoder: { subkey, 0 } } }
  end
  def init_encoder(%{ type: :stream, key: key }=c, iv) do
    { iv, %{ c | encoder: { key, iv, 0 } } }
  end
  def init_encoder(%{ type: :block, key: key, method: method }=c, iv) do
    encoder = :crypto.crypto_init(:"#{method}128", key, iv, true)
    { iv, %{ c | encoder: encoder } }
  end
  def init_encoder(%{ type: :ctr, key: key, method: method }=c, iv) do
    encoder = :crypto.crypto_init(method, key, iv, true)
    { iv, %{ c | encoder: encoder } }
  end

  @spec encode(t, data::binary) :: { :ok, t, res::binary }
  def encode(%Cipher{ type: type }=c, data)
  when type in [:aead, :ss2022] do
    with {:ok, encoder, res} <- _sodium_aead_encode(c.method, c.encoder, data),
    do: {:ok, %{c| encoder: encoder }, res}
  end
  def encode(%Cipher{ type: :stream }=c, data) do
    with { :ok, encoder, res } <- _sodium_stream_encode(data, c.encoder, & @sodium_stream[c.method].xor_ic/4) do
      { :ok, %{ c | encoder: encoder }, res }
    end
  end
  def encode(%Cipher{ type: t }=c, data) when t in [:block, :ctr] do
    result = :crypto.crypto_update(c.encoder, data)
    { :ok, c, result}
  end

  @spec init_decoder( t, iv::binary) :: t
  def init_decoder(%{ type: type, key: key }=c, salt)
  when type in [:aead, :ss2022] do
    subkey = compute_subkey(type, key, salt)
    %{ c | decoder: { subkey, 0 } }
  end
  def init_decoder(%{ type: :stream, key: key }=c, iv) do
    %{ c | decoder: { key, iv, 0 } }
  end
  def init_decoder(%{ type: :block, key: key, method: method }=c, iv) do
    decoder = :crypto.crypto_init(:"#{method}128", key, iv, false)
    %{ c | decoder: decoder }
  end
  def init_decoder(%{ type: :ctr, key: key, method: method }=c, iv) do
    decoder = :crypto.crypto_init(method, key, iv, false)
    %{ c | decoder: decoder }
  end

  def decode(%Cipher{ type: type }=c, data) when type in [:aead, :ss2022] do
    with {:ok, decoder, res} <- _sodium_aead_decode(c.method, c.decoder, data) do
      {:ok, %{c| decoder: decoder}, res}
    end
  end
  def decode(%Cipher{ type: :stream }=c, data) do
    with { :ok, decoder, res } <- _sodium_stream_encode(data, c.decoder, & @sodium_stream[c.method].xor_ic/4) do
      { :ok, %{ c | decoder: decoder }, res }
    end
  end
  def decode(%Cipher{ type: t }=c, data) when t in [:block, :ctr] do
    result = :crypto.crypto_update(c.decoder, data)
    {:ok, c, result}
  end
  # }}}
  
  @doc """
  Computes {key,iv} pair as OpenSSL's `EVP_BytesToKey()` does, or computes { key, salt } for AEAD ciphers.
  """
  @spec compute_key(atom() | String.t, key_len::integer, iv_len::integer) :: binary
  def compute_key(password, key_len, iv_len) do
    _evp_bytes_to_key(password, key_len, iv_len)
  end

  @doc """
  Computes subkey for AEAD encryption using master key and salt
  """
  @spec compute_subkey( atom, binary, String.t ) :: binary
  def compute_subkey(:aead, key, salt) do
    HKDF.derive(:sha, key, 32, salt, "ss-subkey")
  end
  def compute_subkey(:ss2022, key, salt) do
    Blake3.derive_key("shadowsocks 2022 session subkey", key <> salt)
  end

  @spec _generate_iv( len::integer ) :: binary()
  defp _generate_iv(len), do: :crypto.strong_rand_bytes(len)

  # Equivalent to OpenSSL's `EVP_BytesToKey()`
  defp _evp_bytes_to_key(password, key_len, iv_len) do
    _evp_bytes_to_key(password, key_len, iv_len, "")
  end
  defp _evp_bytes_to_key(_password, key_len, iv_len, bytes) when byte_size(bytes) > key_len + iv_len do
    <<key::bytes-size(key_len), _iv::binary-size(iv_len), _::bytes>> = bytes
    key
  end
  defp _evp_bytes_to_key(password, key_len, iv_len, bytes) do
    _evp_bytes_to_key(password, key_len, iv_len, bytes <> :crypto.hash(:md5, bytes <> password))
  end

  defp _pad(str, count), do: String.duplicate(<<0>>, count) <> str

  defp _unpad(str, count) do
    <<_pad::bytes-size(count), res::bytes>> = str
    res
  end

  defp _sodium_stream_encode(bytes, { key, iv, c }, method) do
    padding = rem( c, @sodium_block_size )
    ic      = div( c, @sodium_block_size )
    res = bytes
          |> _pad(padding)
          |> method.(iv, ic, key)
    case res do
      { :ok, str } ->
        data = _unpad(str, padding)
        { :ok, {key, iv, c + byte_size(data) }, data }
      e -> e
    end
  end

  defp _sodium_aead_encode(method, { key, nonce }, bytes) do
    mod = @sodium_aead[method]
    with { :ok, res } <- mod.encrypt( bytes, <<>>, nil, _aead_nonce(method, nonce), key) do
      { :ok, { key, nonce+1 }, res }
    end
  end
  defp _sodium_aead_decode(method, { key, nonce }, bytes) do
    mod = @sodium_aead[method]
    with { :ok, res } <- mod.decrypt( nil, bytes, <<>>, _aead_nonce(method, nonce), key) do
      { :ok, { key, nonce+1 }, res }
    end
  end

  defp _aead_nonce(:xchacha20_ietf_poly1305, int), do: <<int::little-192>>
  defp _aead_nonce(_, int), do: <<int::little-96>>

  def parse_name(str) do
    str
    |> String.downcase
    |> String.replace("-", "_")
    |> String.replace(~r/^\d{4}_/, "")  # remove "2022-" prefix for "2022-blake3..."
    |> String.to_atom
  end

  def info(method), do: Map.get(@ciphers, method)
end
