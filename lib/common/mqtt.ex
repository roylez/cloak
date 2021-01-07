
defmodule Common.MQTT do
  defmacro __using__(otp_app: app) do
    quote do
      use GenServer
      require Logger

      defstruct [ :client_id ]

      def init( _ ) do
        opts   = Application.get_env(unquote(app), __MODULE__)
        host   = Keyword.get(opts, :host)
        port   = Keyword.get(opts, :port, 1883)
        topics = Keyword.get(opts, :topics, [])
        opts   = Keyword.update(opts, :client_id, node(), &( if &1 == "", do: node(), else: &1) )
        id     = opts[:client_id]
        opts = opts
               |> Keyword.put(:server, {Tortoise.Transport.Tcp, host: host, port: port})
               |> Keyword.put(:handler, {opts[:handler], [id,  __MODULE__ ]})
               |> Keyword.put(:subscriptions, _parse_topics(topics, id))
        Logger.debug "Connecting to MQTT with: "
        Logger.debug inspect(opts)
        Tortoise.Supervisor.start_child(opts)
        { :ok, %__MODULE__{ client_id: id } }
      end

      def start_link(opts) do
        GenServer.start_link(__MODULE__, opts, name: __MODULE__)
      end

      def publish(topic, payload, opts \\ %{}),       do: GenServer.cast(__MODULE__, { :publish, topic, payload, opts })
      def publish_batch(topic, payload, opts \\ %{}), do: publish(topic, payload, Map.put(opts, :batch, true))

      def handle_cast({:publish, topic, payload, opts}, state) when not is_binary(topic) do
        handle_cast({:publish, _join_topic(topic), payload, opts }, state)
      end

      def handle_cast({:publish, topic, payload, %{ with_id: true }=opts }, state ) do
        topic_with_id = [ topic, state.client_id ] |> Stream.map(&to_string/1) |> Enum.join("/")
        handle_cast({:publish, topic_with_id, payload, Map.delete(opts, :with_id)}, state)
      end

      def handle_cast({:publish, topic, payloads, %{ batch: true }=opts }, state ) when is_list(payloads) do
        handle_cast({:publish, topic, payloads, Map.put(opts, :batch, 30) }, state )
      end

      def handle_cast({:publish, _topic, [], %{ batch: _ } }, state ), do: { :noreply, state }

      def handle_cast({:publish, topic, payloads, %{ batch: batch }=opts }, state )
      when is_list(payloads) and is_integer(batch) do
        payloads
        |> Stream.chunk_every(batch)
        |> Enum.map(&( publish(topic, [ "batch" | &1 ], Map.delete(opts, :batch) ) ) )
        { :noreply, state }
      end

      def handle_cast({:publish, topic, payload, opts}, state) when is_binary(payload) do
        Logger.info "MQTT -> #{topic}, #{payload}"
        Tortoise.publish(state.client_id, topic, payload)
        { :noreply, state }
      end

      def handle_cast({:publish, topic, payload, opts}, state) when not is_binary(payload) do
        Logger.info "MQTT -> #{topic}, #{_sanitize(payload)}"
        Tortoise.publish(state.client_id, topic, Jason.encode!(payload))
        { :noreply, state }
      end

      defp _sanitize(%{ passwd:   _ }=payload), do: inspect %{ payload | passwd:   "[FILTERED]" }
      defp _sanitize(%{ password: _ }=payload), do: inspect %{ payload | password: "[FILTERED]" }
      defp _sanitize( payload ) when is_list(payload), do: "[#{ Enum.map(payload, &( _sanitize(&1) )) |> Enum.join(",")}]"
      defp _sanitize( payload ), do: inspect(payload)

      defp _parse_topics(topics, client_id) do
        topics
        |> Enum.map(&( String.replace(&1, "SELF", to_string(client_id)) ))
      end

      defp _join_topic(topic) when is_tuple(topic), do: _join_topic(Tuple.to_list(topic))
      defp _join_topic(topic) do
	topic
	|> Stream.map( &(to_string(&1)) )
	|> Enum.join("/")
      end
    end
  end
end
