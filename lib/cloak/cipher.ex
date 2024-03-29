defmodule Cloak.Cipher do
  @moduledoc """
  Crypto related functions
  """

  @type method :: atom()
  @type ctx :: tuple()
  @type t :: %__MODULE__{}

  alias __MODULE__

  defstruct [
    method:  nil,     # encryption method
    key:     nil,     # derived key or aead master key
    # encoding context
    #   stream:       erl crypto state reference
    #   AEAD:         { subkey, nonce }
    encoder:  nil,
    decoder:  nil,
    key_len:  0,       # key size
    iv_len:   0,       # iv/salt size
    type:     :stream, # cipher type, aead / stream
    category: :aead,   # algorithm category
    algo:     nil,     # internal agorithm name
  ]

  @methods %{
    # { category, type, algo, key_len, iv_len | salt_len }
    aes_128_ctr:        { :stream, :stream, :aes_128_ctr,    16, 16 },
    aes_192_ctr:        { :stream, :stream, :aes_192_ctr,    24, 16 },
    aes_256_ctr:        { :stream, :stream, :aes_256_ctr,    32, 16 },
    aes_128_cfb:        { :stream, :stream, :aes_128_cfb128, 16, 16 },
    aes_192_cfb:        { :stream, :stream, :aes_192_cfb128, 24, 16 },
    aes_256_cfb:        { :stream, :stream, :aes_256_cfb128, 32, 16 },
    aes_128_gcm:        { :aead,   :aead,   :aes_128_gcm,    16, 16 },
    aes_256_gcm:        { :aead,   :aead,   :aes_256_gcm,    32, 32 },
    blake3_aes_256_gcm: { :ss2022, :aead,   :aes_256_gcm,    32, 32 },
  }

  @doc """
  computes key or masterkey
  """
  @spec setup(atom | String.t, passwd::String.t ) :: { :ok, t } | { :error, :invalid_method }
  def setup(method, passwd) when is_binary(method) do
    method |> parse_name() |> setup(passwd)
  end
  def setup(method, _passwd) when not is_map_key(@methods, method), do: { :error, :invalid_method }
  def setup(method, passwd) do
    { category, type, algo, key_len, iv_len } = @methods[method]
    res = %__MODULE__{ method: method, key_len: key_len, iv_len: iv_len, type: type, algo: algo, category: category }
    if category == :ss2022 do
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
  def stream_encode(%Cipher{ category: :aead }=c, data) when byte_size(data) > 0x3FFF do
    { :ok, c , res }  = stream_encode(c, binary_part(data, 0, 0x3FFF))
    { :ok, c , more } = stream_encode(c, binary_part(data, 0x3FFF, byte_size(data)-0x3FFF))
    { :ok, c , res <> more }
  end
  def stream_encode(%Cipher{ category: :ss2022 }=c, data) when byte_size(data) > 0xFFFF do
    { :ok, c , res }  = stream_encode(c, binary_part(data, 0, 0xFFFF))
    { :ok, c , more } = stream_encode(c, binary_part(data, 0xFFFF, byte_size(data)-0xFFFF))
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
  def stream_decode(%Cipher{type: :aead, decoder: { key, nonce} }=c, data) do
    { :ok, %{ c| decoder: { key, nonce, data } }, "" }
  end
  def stream_decode(%Cipher{}=c, data), do: decode(c, data)

  @spec init_encoder( t ) :: { iv::binary, t }
  def init_encoder(%{ iv_len: len }=c), do: init_encoder(c, len)

  @spec init_encoder( t, integer ) :: { iv::binary, t }
  def init_encoder(c, len) when is_integer(len), do: init_encoder(c, _generate_iv(len))

  @spec init_encoder( t, binary ) :: { iv::binary, t }
  def init_encoder(%{ type: :aead, key: key }=c, salt) do
    subkey = compute_subkey(c.category, key, salt)
    { salt, %{ c | encoder: { subkey, 0 } } }
  end
  def init_encoder(%{ type: :stream, key: key, algo: algo }=c, iv) do
    encoder = :crypto.crypto_init(algo, key, iv, true)
    { iv, %{ c | encoder: encoder } }
  end

  @spec encode(t, data::binary) :: { :ok, t, res::binary }
  def encode(%Cipher{ type: :aead, encoder: { key, nonce } }=c, data) do
    { res, tag } = :crypto.crypto_one_time_aead(c.algo, key, <<nonce::little-96>>, data, <<>>, true)
    { :ok, %{ c | encoder: { key, nonce+1 } }, res <> tag }
  end
  def encode(%Cipher{ type: :stream }=c, data) do
    result = :crypto.crypto_update(c.encoder, data)
    { :ok, c, result}
  end

  @spec init_decoder( t, iv::binary) :: t
  def init_decoder(%{ type: :aead, key: key }=c, salt) do
    subkey = compute_subkey(c.category, key, salt)
    %{ c | decoder: { subkey, 0 } }
  end
  def init_decoder(%{ type: :stream, key: key, algo: algo }=c, iv) do
    decoder = :crypto.crypto_init(algo, key, iv, false)
    %{ c | decoder: decoder }
  end

  def decode(%Cipher{ type: :aead, decoder: {key, nonce} }=c, data) when byte_size(data) <= 16 do
    { :error, :forged }
  end
  def decode(%Cipher{ type: :aead, decoder: {key, nonce} }=c, data) do
    payload_len = byte_size(data) - 16
    { payload, tag } = :erlang.split_binary(data, payload_len)
    case :crypto.crypto_one_time_aead(c.algo, key, <<nonce::little-96>>, payload, <<>>, tag, false) do
      res when is_binary(res) -> { :ok, %{ c | decoder: { key, nonce+1 } }, res }
      :error -> { :error, :forged }
    end
  end
  def decode(%Cipher{ type: :stream }=c, data) do
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
    HKDF.derive(:sha, key, byte_size(salt), salt, "ss-subkey")
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

  def parse_name(str) do
    str
    |> String.downcase
    |> String.replace("-", "_")
    |> String.replace(~r/^\d{4}_/, "")  # remove "2022-" prefix for "2022-blake3..."
    |> String.to_atom
  end

  def info(method), do: Map.get(@methods, method)
end
