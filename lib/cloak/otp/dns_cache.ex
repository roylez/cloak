defmodule Cloak.DNSCache do
  use Common.Cache, ttl: 120

  def default_fallback(addr) do
    # addr can be a string of IP or hostname, both can be handled by
    # :inet.getaddr/2
    # In case addr is random nonsense, an Exception is raised by :to_charlist/1
    addr_cl = to_charlist(addr)
    case :inet.getaddr(addr_cl, :inet) do
      { :ok, ip } -> { :commit, ip }
      _ -> { :ignore, { :nxdomain, addr } }
    end
  end
end
