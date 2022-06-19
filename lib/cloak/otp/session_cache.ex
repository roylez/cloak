defmodule Cloak.SessionCache do
  use Common.Cache, ttl: 60
end
