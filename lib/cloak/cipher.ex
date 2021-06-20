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
    xchacha20_ietf_poly1305: { 32, 32, :aead }
  }
  @sodium_block_size 64
  @sodium_aead %{ 
    aes_256_gcm:             Salty.Aead.Aes256gcm,
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
  def setup(method, passwd) when is_binary(method), do: setup(_parse_method(method), passwd)
  def setup(method, passwd) do
    case @ciphers[method] do
      { key_len, iv_len, type } ->
        { :ok,
          %__MODULE__{
            key: compute_key(passwd, key_len, iv_len),
            method: method,
            key_len: key_len,
            iv_len: iv_len,
            type: type }
        }
      _ -> { :error, :invalid_method }
    end
  end

  @spec stream_encode( t, data::binary ) :: { :ok, t, res::binary }
  def stream_encode(%Cipher{}=c, ""), do: { :ok, c, "" }
  def stream_encode(%Cipher{ type: :aead }=c, data) when byte_size(data) > 0x3FFF do
    { :ok, c , res }  = stream_encode(c, binary_part(data, 0, 0x3FFF))
    { :ok, c , more } = stream_encode(c, binary_part(data, 0x3FFF, byte_size(data)-0x3FFF))
    { :ok, c , res <> more }
  end
  def stream_encode(%Cipher{ type: :aead }=c, data) do
    l = byte_size(data)
    { :ok, c, len } = encode(c, << l::16 >>)
    { :ok, c, res } = encode(c, data)
    { :ok, c, len <> res }
  end
  def stream_encode(%Cipher{}=c, data), do: encode(c, data)
  
  @spec stream_decode( t, data::binary ) :: { :ok, t, res::binary }

  def stream_decode(%Cipher{}=c, ""), do: { :ok, c, "" }
  def stream_decode(%Cipher{type: :aead, decoder: {key, nonce, buf}}=c, data) do
    stream_decode(%{c|decoder: {key, nonce}}, buf<>data)
  end
  def stream_decode(%Cipher{type: :aead}=c, <<len::bytes-18, rest::bytes>>=data) do
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
  def stream_decode(%Cipher{type: :aead, decoder: { key, nonce} }=c, data), do: { :ok, %{ c| decoder: { key, nonce, data } }, "" }
  def stream_decode(%Cipher{}=c, data), do: decode(c, data)

  @spec init_encoder( t ) :: { iv::binary, t }
  def init_encoder(c) do
    iv  = _generate_iv(c.iv_len)
    case c.type do
      :aead -> 
        key = compute_aead_subkey(c.key, iv)
        { iv, %{ c | encoder: { key, 0          } } }
      :stream -> 
        { iv, %{ c | encoder: { c.key, iv, 0    } } }
      :block ->
        encoder = :crypto.crypto_init(:"#{c.method}128", c.key, iv, true)
        { iv, %{ c | encoder: encoder } }
      :ctr ->
        encoder = :crypto.crypto_init(c.method, c.key, iv, true)
        { iv, %{ c | encoder: encoder } }
    end
  end

  @spec encode(t, data::binary) :: { :ok, t, res::binary }
  def encode(%Cipher{ type: :aead }=c, data) do
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
  def init_decoder(c, iv) do
    case c.type do
      :aead -> 
        key = compute_aead_subkey(c.key, iv)
        %{ c | decoder: { key, 0          } }
      :stream -> 
        %{ c | decoder: { c.key, iv, 0    } }
      :block ->
        decoder = :crypto.crypto_init(:"#{c.method}128", c.key, iv, false)
        %{ c | decoder: decoder }
      :ctr ->
        decoder = :crypto.crypto_init(c.method, c.key, iv, false)
        %{ c | decoder: decoder }
    end
  end

  def decode(%Cipher{ type: :aead }=c, data) do
    with {:ok, decoder, res} <- _sodium_aead_decode(c.method, c.decoder, data),
    do: {:ok, %{c| decoder: decoder}, res}
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
  @spec compute_aead_subkey( binary, String.t ) :: binary
  def compute_aead_subkey(key, salt) do
    HKDF.derive(:sha, key, 32, salt, "ss-subkey")
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
    with { :ok, res } <- mod.encrypt( bytes, <<>>, nil, _aead_nonce(method, nonce), key)
    do
      { :ok, { key, nonce+1 }, res }
    end
  end
  defp _sodium_aead_decode(method, { key, nonce }, bytes) do
    mod = @sodium_aead[method]
    with { :ok, res } <- mod.decrypt( nil, bytes, <<>>, _aead_nonce(method, nonce), key)
    do
      { :ok, { key, nonce+1 }, res }
    end
  end

  defp _aead_nonce(:xchacha20_ietf_poly1305, int), do: <<int::little-192>>
  defp _aead_nonce(_, int), do: <<int::little-96>>

  defp _parse_method(str) do
    str
    |> String.downcase
    |> String.replace("-", "_")
    |> String.to_atom
  end
end
