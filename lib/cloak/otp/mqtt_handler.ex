require Logger

defmodule Cloak.MQTTHandler do
  use Tortoise.Handler

  defstruct ~w( client_id callback )a

  alias Cloak.Account

  @spec init( list() )  :: { :ok, state :: term }
  def init( [id, callback ]), do: { :ok, %__MODULE__{ client_id: id, callback: callback }}

  def subscription(:up, "port/+/" <> _id = topic, state) do
    Logger.info "MQTT subscribing: #{topic}"
    state.callback.publish("node/start", nil, %{ with_id: true })
    { :ok, state }
  end

  def subscription(:up, topic, state) do
    Logger.info "MQTT subscribing: #{topic}"
    { :ok, state }
  end

  def connection(type, state) do
    Logger.info "MQTT connection #{to_string(type) |> String.upcase}"
    { :ok, state }
  end

  def handle_message(topic, payload, state) when is_list(topic) do
    Logger.debug "MQTT <- #{Enum.join(topic, "/")}: #{payload}"
    topic = topic
            |> Enum.map( &String.to_atom/1 )
            |> List.to_tuple()
    handle_message(topic, payload, state)
  end

  def handle_message(topic, payload, state) when is_tuple(topic) and is_binary(payload) do
    case Jason.decode(payload, keys: :atoms) do
      { :ok, data } -> handle(topic, data, state)
      { :error, _ } -> handle(topic, payload, state )
    end
    { :ok, state }
  end

  def handle( topic, [ "batch" | payloads ], state), do: Enum.map(payloads, &( handle(topic, &1, state) ))

  def handle({ :board, :start }, ports, state) do
    Logger.info "MQTT <- board/start, #{inspect ports}"
    ports_to_start = Enum.reject(ports, &( Cloak.Registry.where({:worker, &1})) )
    if length(ports_to_start) != 0 do
      state.callback.publish("node/request", ports_to_start, %{ with_id: true })
    end
  end

  # messages:
  #   # start / restart
  #   port/start      %{ port: _, passwd: _, method: _ }
  #   # stop
  #   port/stop       %{ port: _ }
  #   # alias to port/start
  #   port/restart    %{ port: _, passwd: _, method: _ }
  #
  # addressed to self
  def handle( { :port, act, _c }, msg, state), do: handle({:port, act}, msg, state)

  def handle( { :port, start }, %{ port: port, method: method, passwd: passwd }, _state)
  when start in ~w(start restart)a do
    Account.add(%{ port: port, method: method, passwd: passwd })
  end

  def handle({ :port, :stop }, %{ port: port }, _state) do
    Account.remove(port)
  end

  def handle( topic, payload, _state ) do
    Logger.warn "MQTT unknown message #{inspect topic}: #{inspect payload}"
  end
end
