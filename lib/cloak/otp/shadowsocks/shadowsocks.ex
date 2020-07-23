defmodule Cloak.Shadowsocks do
  use DynamicSupervisor
  import Cloak.Registry
  @moduledoc """
  Module to manage ports used
  """

  @type account() :: Cloak.Account.t()

  def start_link(_) do
    DynamicSupervisor.start_link(__MODULE__, nil, name: __MODULE__)
  end

  def init(_) do
    DynamicSupervisor.init(strategy: :one_for_one)
  end

  @doc """
  Start a new port or reload a already start port
  """
  @spec start_worker( account() ) :: any()
  def start_worker( %{ port: _, method: _, passwd: _ }=account ) do
    DynamicSupervisor.start_child( __MODULE__, { Cloak.Shadowsocks.Worker, account })
  end

  def start_worker(_), do: nil

  @doc """
  Stops a port
  """
  @spec stop_worker( integer() | account() | pid() ) :: any()
  def stop_worker( port ) when is_integer(port) do
    case where({:worker, port}) do
      nil -> :ok
      pid ->
        DynamicSupervisor.terminate_child( __MODULE__, pid )
    end
  end
  def stop_worker( %{ port: port } ), do: stop_worker( port )
  def stop_worker( pid ) when is_pid(pid), do: DynamicSupervisor.terminate_child( __MODULE__, pid )

  def stop_worker( _ ), do: nil

  @doc """
  Returns currently opened port count
  """
  @spec count_workers() :: integer()
  def count_workers do
    DynamicSupervisor.which_children(__MODULE__) |> length()
  end
end

