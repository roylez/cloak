defmodule Cloak.CipherTest do
  use ExUnit.Case, async: true
  alias Cloak.Cipher

  @passwd    "foQuC36lejke0X0FkHBbVAJAWiZlGtFO5vKhiduv+is="
  @data      "Something needs to be encrypted"
  @more_data "One thing I've learned in the woods is that there is no such thing as random. Everything is steeped in meaning, colored by relationships, one thing with another."
  @methods ~w(
    aes_128_ctr
    aes_192_ctr
    aes_256_ctr
    aes_128_cfb
    aes_192_cfb
    aes_256_cfb
    aes_128_gcm
    aes_256_gcm
  )a

  for method <- @methods do
    test "#{method} encode/decode" do
      { :ok, c } = Cipher.setup(unquote(method), @passwd)
      { iv, c  } = Cipher.init_encoder(c)
      c = Cipher.init_decoder(c, iv)

      { :ok, _, res }  = Cipher.encode(c, @data)
      { :ok, _, data } = Cipher.decode(c, res)
      assert data == @data
    end

    test "#{method} stream_encode/stream_decode" do
      { :ok, c } = Cipher.setup(unquote(method), @passwd)
      { iv, c  } = Cipher.init_encoder(c)
      c = Cipher.init_decoder(c, iv)

      { :ok, c,  res } = Cipher.stream_encode(c, @data)
      { :ok, c, more } = Cipher.stream_encode(c, @more_data)
      { :ok, c, data } = Cipher.stream_decode(c, res)
      { :ok, _, more_data } = Cipher.stream_decode(c, more)

      assert data == @data
      assert more_data == @more_data
    end

    test "#{method} stream_encode/stream_decode with different decode chunk size" do
      { :ok, c } = Cipher.setup(unquote(method), @passwd)
      { iv, c  } = Cipher.init_encoder(c)
      c = Cipher.init_decoder(c, iv)

      { :ok, c,  res } = Cipher.stream_encode(c, @data)
      { :ok, c, more } = Cipher.stream_encode(c, @more_data)
      { :ok, _, all  } = Cipher.stream_decode(c, res<>more)

      assert all == @data <> @more_data
    end
  end
end
