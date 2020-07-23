defmodule Cloak.Registry do

  def via( key ),   do: {:via, Registry, {__MODULE__, key}}

  def where( key ) do
    case Registry.lookup( __MODULE__, key ) do
      [{pid, _}] -> pid
      [ ]        -> nil
    end
  end

end
