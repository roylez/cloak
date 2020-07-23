require Logger

defmodule Cloak.Bookkeeper do
  use   GenServer
  alias Cloak.MQTT

  @dump_interval 300_000

  def start_link(_) do
    GenServer.start_link(__MODULE__, nil, [name: __MODULE__])
  end

  def init(_) do
    Process.send_after(self(), :dump, @dump_interval)
    { :ok, nil }
  end

  def record_usage( port, u, d ) do
    GenServer.cast(__MODULE__, { :record, port, u, d })
  end

  def handle_cast({:record, key, u, d}, table ) do
    :ets.update_counter(table, key, [{2, u}, {3, d}], { key, 0, 0 })
    { :noreply, table }
  end

  # dump all records to db
  #
  def handle_info(:dump, table) do
    usage = table
            |> :ets.tab2list()
            # if either u == 0 or d == 0, then there is no valid transfer
            |> Stream.reject( &( match?({ _, 0, _}, &1) || match?({ _, _, 0 }, &1) ) )
            |> Enum.map( &Tuple.to_list/1 )
    MQTT.publish_batch("usage", usage )
    :ets.delete_all_objects(table)
    Process.send_after(self(), :dump, @dump_interval)
    { :noreply, table }
  end

  # ETS transfer from TableAdmin
  def handle_info({:"ETS-TRANSFER", tab, _from, _}, _ ) do
    { :noreply, tab }
  end

end
