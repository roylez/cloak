# http://steve.vinoski.net/blog/2011/03/23/dont-lose-your-ets-tables/
#
# The Erlang supervisor creates a table manager process. Since all this process
# does is manage the table, the likelihood of it crashing is very low.
#
# The table manager links itself to the table user process and traps exits,
# allowing it to receive an EXIT message if the table user process dies
# unexpectedly.
#
# The table manager creates a table, names itself (self()) as the heir, and then
# gives it away to the table user process.
#
# If the table user process dies, the table manager is informed of the process
# death and also inherits the table back.

require Logger

defmodule Common.TableManager do
  use GenServer

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, [name: __MODULE__])
  end

  def init(opts) do
    table_name    = Keyword.get(opts, :table_name)
    user_proccess = Keyword.get(opts, :table_user)
    Process.flag( :trap_exit , true )
    table = :ets.new(table_name, [:named_table, {:heir, self(), nil}])
    Process.send_after(self(), :give_away, 1)
    { :ok, { table_name, table, user_proccess } }
  end

  def handle_info({ :EXIT, from, _reason }, {table_name, _table, process} = state) do
    Logger.debug "EXIT received from #{inspect from}"
    _give_away(process, table_name)
    { :noreply, state }
  end

  def handle_info({:"ETS-TRANSFER", tab, _from, _}, state ) do
    Logger.debug "Table #{tab} transferred to TableManager"
    { :noreply, state }
  end

  def handle_info(:give_away, state) do
    { _table_name, table, process } = state
    _give_away(process, table )
    { :noreply, state }
  end

  defp _give_away(process, table) do
    pid = _wait_for_respawn(process)
    Logger.debug "Table user process #{inspect process} is alive #{inspect pid}"
    Process.link(pid)
    :ets.give_away(table, pid, nil)
    Logger.debug "Table #{table} transferred to #{inspect pid}"
  end

  defp _wait_for_respawn(process) do
    case Process.whereis(process) do
      nil -> _wait_for_respawn(process)
      pid -> pid
    end
  end
end
