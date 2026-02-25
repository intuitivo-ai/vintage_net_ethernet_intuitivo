defmodule VintageNetEthernet.DnsForwarder do
  @moduledoc """
  DNS forwarder that resolves local records directly and forwards
  everything else to upstream DNS servers.

  Replaces Busybox dnsd so that a single DNS IP (e.g. 192.168.24.1)
  can serve both local hostnames (wizard URL) and internet queries.

  ## Options

    * `:bind_ip`  - IP tuple to bind the listening socket (required)
    * `:port`     - UDP port (default 53)
    * `:records`  - list of `{hostname, ip_tuple}` for local resolution (required)
    * `:upstream`  - list of upstream DNS IP tuples to forward to (required)
    * `:ttl`      - TTL in seconds for local responses (default 60)
  """

  use GenServer
  require Logger

  @default_port 53
  @default_ttl 60
  @pending_cleanup_ms 30_000
  @upstream_timeout_ms 5_000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl GenServer
  def init(opts) do
    bind_ip = Keyword.fetch!(opts, :bind_ip)
    port = Keyword.get(opts, :port, @default_port)
    records = Keyword.fetch!(opts, :records)
    upstream = Keyword.fetch!(opts, :upstream)
    ttl = Keyword.get(opts, :ttl, @default_ttl)

    udp_opts = [:binary, {:ip, bind_ip}, {:active, true}, {:reuseaddr, true}]

    with {:ok, listen} <- :gen_udp.open(port, udp_opts),
         {:ok, fwd} <- :gen_udp.open(0, [:binary, {:active, true}]) do
      Process.send_after(self(), :cleanup_pending, @pending_cleanup_ms)

      state = %{
        listen: listen,
        fwd: fwd,
        records: normalize_records(records),
        upstream: upstream,
        ttl: ttl,
        pending: %{}
      }

      Logger.info(
        "[DnsForwarder] Listening on #{:inet.ntoa(bind_ip)}:#{port}, " <>
          "upstream=#{inspect(upstream)}, local_records=#{length(records)}"
      )

      {:ok, state}
    else
      {:error, reason} ->
        Logger.error("[DnsForwarder] Failed to open socket: #{inspect(reason)}")
        {:stop, {:socket_error, reason}}
    end
  end

  # --- Incoming query on the local listening socket ---
  @impl GenServer
  def handle_info({:udp, sock, client_ip, client_port, data}, %{listen: sock} = state) do
    state =
      case lookup_local(data, state.records) do
        {:ok, qname, ip} ->
          response = build_a_response(data, ip, state.ttl)
          :gen_udp.send(sock, client_ip, client_port, response)
          Logger.debug("[DnsForwarder] Local hit: #{qname}")
          state

        :no_match ->
          forward_upstream(data, client_ip, client_port, state)
      end

    {:noreply, state}
  end

  # --- Response arriving from upstream ---
  def handle_info({:udp, sock, _ip, _port, data}, %{fwd: sock} = state) do
    state =
      with {:ok, tx_id} <- tx_id(data),
           {{client_ip, client_port, _ts}, pending} <- Map.pop(state.pending, tx_id) do
        :gen_udp.send(state.listen, client_ip, client_port, data)
        %{state | pending: pending}
      else
        _ -> state
      end

    {:noreply, state}
  end

  # --- Periodic cleanup of stale pending entries ---
  def handle_info(:cleanup_pending, state) do
    now = System.monotonic_time(:millisecond)

    pending =
      Map.reject(state.pending, fn {_id, {_ip, _port, ts}} ->
        now - ts > @upstream_timeout_ms
      end)

    Process.send_after(self(), :cleanup_pending, @pending_cleanup_ms)
    {:noreply, %{state | pending: pending}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl GenServer
  def terminate(_reason, state) do
    :gen_udp.close(state.listen)
    :gen_udp.close(state.fwd)
    :ok
  end

  # ── Helpers ──────────────────────────────────────────────────────

  defp normalize_records(records) do
    Enum.map(records, fn {name, ip} -> {String.downcase(name), ip} end)
  end

  defp lookup_local(packet, records) do
    with {:ok, qname, _tx} <- parse_query_name(packet) do
      lower = String.downcase(qname)

      case List.keyfind(records, lower, 0) do
        {_, ip} -> {:ok, qname, ip}
        nil -> :no_match
      end
    else
      _ -> :no_match
    end
  end

  defp forward_upstream(data, client_ip, client_port, state) do
    with {:ok, tx_id} <- tx_id(data) do
      [primary | _] = state.upstream
      :gen_udp.send(state.fwd, primary, @default_port, data)
      ts = System.monotonic_time(:millisecond)
      pending = Map.put(state.pending, tx_id, {client_ip, client_port, ts})
      %{state | pending: pending}
    else
      _ -> state
    end
  end

  # Transaction ID = first 2 bytes
  defp tx_id(<<id::16, _::binary>>), do: {:ok, id}
  defp tx_id(_), do: :error

  # DNS header is 12 bytes; question section follows.
  # Parse the QNAME (sequence of length-prefixed labels terminated by 0).
  defp parse_query_name(<<tx::16, _flags::16, _qd::16, _an::16, _ns::16, _ar::16, body::binary>>) do
    case decode_name(body, []) do
      {:ok, labels, _rest} ->
        {:ok, Enum.join(labels, "."), tx}

      :error ->
        :error
    end
  end

  defp parse_query_name(_), do: :error

  defp decode_name(<<0, rest::binary>>, acc), do: {:ok, Enum.reverse(acc), rest}

  defp decode_name(<<len::8, label::binary-size(len), rest::binary>>, acc) when len > 0 and len <= 63 do
    decode_name(rest, [label | acc])
  end

  defp decode_name(_, _), do: :error

  # Build a minimal valid DNS A-record response from the original query packet.
  # Re-uses the question section verbatim via a name-pointer (0xC00C → offset 12).
  defp build_a_response(query, {a, b, c, d}, ttl) do
    <<tx_id::binary-size(2), _flags::binary-size(2), _rest::binary>> = query

    # QR=1 response, AA=1 authoritative, RD=1 recursion desired (echo), RA=0, RCODE=0
    flags = <<0x84, 0x00>>

    # 1 question, 1 answer, 0 authority, 0 additional
    counts = <<0, 1, 0, 1, 0, 0, 0, 0>>

    # Extract question section (QNAME + QTYPE + QCLASS)
    <<_header::binary-size(12), qsection::binary>> = query
    {question, _} = split_question(qsection)

    # Answer RR: name pointer 0xC00C, type A=1, class IN=1, TTL, rdlen=4, rdata
    answer =
      <<0xC0, 0x0C, 0, 1, 0, 1>> <>
        <<ttl::32>> <>
        <<0, 4, a, b, c, d>>

    tx_id <> flags <> counts <> question <> answer
  end

  # Walk past QNAME + 4 bytes (QTYPE 2B + QCLASS 2B) and return {question_bytes, rest}
  defp split_question(data) do
    case skip_name(data, 0) do
      {:ok, name_len} ->
        total = name_len + 4
        <<q::binary-size(total), rest::binary>> = data
        {q, rest}

      :error ->
        {data, <<>>}
    end
  end

  defp skip_name(<<0, _::binary>>, acc), do: {:ok, acc + 1}

  defp skip_name(<<len::8, _::binary-size(len), rest::binary>>, acc) when len > 0 and len <= 63 do
    skip_name(rest, acc + 1 + len)
  end

  defp skip_name(_, _), do: :error
end
