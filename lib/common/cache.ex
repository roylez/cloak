defmodule Common.Cache do

  defmacro __using__(opts) do
    ttl = Keyword.get(opts, :ttl)

    ast = Cachex.__info__(:functions)
          |> Enum.reject(fn {func, _arity} -> func in [:child_spec, :import, :start_link] end)
          |> Enum.map(fn {func, arity} ->
            args = Macro.generate_arguments(arity - 1, __MODULE__)
            quote do
              def unquote(func)(unquote_splicing(args)), do: apply(Cachex, unquote(func), [__MODULE__ | unquote(args)])
            end
          end)

    other_ast = quote do
      import Cachex.Spec

      def child_spec(_) do
        %{ 
          id: __MODULE__, 
          start: {__MODULE__, :start_link, [nil]},
          type: :supervisor,
          restart: :permanent
        }
      end

      def start_link(_) do
        Cachex.start_link(__MODULE__,
          fallback: fallback(default: &default_fallback/1),
          expiration: expiration(default: :timer.seconds(unquote(ttl)))
        )
      end

      def default_fallback(_),    do: { :ignore, nil }
      def default_fallback(_, _), do: { :ignore, nil }

      defoverridable start_link: 1, default_fallback: 1, default_fallback: 2
    end

    [ other_ast | ast ]
  end

end
