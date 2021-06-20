defmodule HKDF do
  @moduledoc """
  Provides a simple Hashed Message Authentication Code (HMAC)-based
  key derivation function (HKDF).

  ## Process

  Keys are derived in two steps:

    1. Extract - a pseudorandom key is extracted from an input key material
                 and optional salt.
    2. Expand - an output key material of a specific length is expanded from
                hashes of the pseudorandom key and an optional info message.

  ## Source

  Defined in [rfc 5859](https://tools.ietf.org/html/rfc5869)
  """
  @type hash_fun :: :md5 | :sha | :sha224 | :sha256 | :sha384 | :sha512
  @type input_key_material :: binary
  @type salt :: binary
  @type pseudorandom_key :: binary
  @type length :: non_neg_integer
  @type info :: binary
  @type output_key_material :: binary

  @doc """
  Dervice a key of a specific length using the specified hash function.

  An optional salt (extract phase) and/or info message (expand phase)
  can be supplied.

  ## Example

      iex> HKDF.derive(:sha256, "some input", 16)
      <<47, 231, 129, 75, 82, 47, 198, 78, 55, 31, 167, 66, 15, 128, 63, 243>>

      iex> HKDF.derive(:sha256, "some input", 16, "salt", "secret message")
      <<28, 213, 201, 204, 16, 226, 160, 120, 69, 47, 46, 58, 15, 255, 54, 52>>

  """
  @spec derive(hash_fun, input_key_material, length, salt, info) :: output_key_material
  def derive(hash_fun, ikm, len, salt \\ "", info \\ "") do
    prk = extract(hash_fun, ikm, salt)
    expand(hash_fun, prk, len, info)
  end

  @doc """
  Extract a psuedorandom key from an input key material.

  ## Example

      iex> HKDF.extract(:sha256, "some input")
      <<130, 6, 35, 29, 160, 13, 100, 90, 127, 71, 104, 2, 139, 88, 204, 124, 201,
        141, 22, 223, 95, 189, 60, 4, 147, 6, 19, 196, 66, 139, 65, 153>>

      iex> HKDF.extract(:sha256, "some input", "salt")
      <<165, 68, 136, 223, 19, 149, 73, 161, 172, 133, 175, 129, 14, 46, 132, 27, 219,
        137, 155, 191, 199, 9, 251, 100, 155, 173, 33, 97, 201, 250, 19, 92>>

  """
  @spec extract(hash_fun, input_key_material, salt) :: pseudorandom_key
  def extract(hash_fun, ikm, salt \\ "") do
    :crypto.mac(:hmac, hash_fun, salt, ikm)
  end

  @doc """
  Expands a pseudorandom key to an output key material of a defined length.

  ## Example

      iex(1)> prk = HKDF.extract(:sha256, "some input", "salt")
      iex(2)> HKDF.expand(:sha256, prk, 16)
      <<227, 13, 8, 99, 198, 12, 203, 171, 124, 253, 132, 131, 59, 202, 95, 24>>

      iex(1)> prk = HKDF.extract(:sha256, "some input", "salt")
      iex(2)> HKDF.expand(:sha256, prk, 16, "secret message")
      <<28, 213, 201, 204, 16, 226, 160, 120, 69, 47, 46, 58, 15, 255, 54, 52>>

  """
  @spec expand(hash_fun, pseudorandom_key, length, info) :: output_key_material
  def expand(hash_fun, prk, len, info \\ "") do
    hash_len = hash_length(hash_fun)
    n = Float.ceil(len/hash_len) |> round()
    full =
      Enum.scan(1..n, "", fn index, prev ->
      data = prev <> info <> <<index>>
      :crypto.mac(:hmac, hash_fun, prk, data)
      end)
      |> Enum.reduce("", &Kernel.<>(&2, &1))
    <<output :: unit(8)-size(len), _ :: binary>> = full
    <<output :: unit(8)-size(len)>>
  end

  for fun <- ~w(md5 sha sha224 sha256 sha384 sha512)a do
    len = fun |> :crypto.hash("") |> byte_size()
    defp hash_length(unquote(fun)) do
      unquote(len)
    end
  end
end
