%%% @doc TLCP/GMSSL Debug Server
%%%
%%% A verbose TLS server that prints EVERY step of the handshake process
%%% so you can see exactly what is happening during the GMSSL/TLCP handshake.
%%%
%%% Usage:
%%%   server:start().           %% Default port 8443, TLCP
%%%   server:start(8443).       %% Custom port
%%%   server:start(8443, tls13). %% TLS 1.3 mode (for non-TLCP debugging)
%%%
-module(server).
-export([start/0, start/1, start/2]).

-define(CERT_DIR, "certs").

start() -> start(8443).
start(Port) -> start(Port, tlcp).
start(Port, Mode) ->
    banner(Port, Mode),

    io:format("~n[STEP 1] Starting SSL application...~n"),
    ssl:start(),
    io:format("  -> ssl application started~n"),

    io:format("~n[STEP 2] Loading certificates & keys...~n"),
    Opts = build_opts(Mode, Port),
    io:format("  -> Options built:~n"),
    lists:foreach(fun({K, V}) ->
        case K of
            certs_keys -> io:format("       ~p => [~p cert/key pairs]~n", [K, length(V)]);
            ciphers    -> io:format("       ~p => ~p~n", [K, V]);
            _          -> io:format("       ~p => ~p~n", [K, V])
        end
    end, Opts),

    io:format("~n[STEP 3] Creating listen socket on port ~p...~n", [Port]),
    case ssl:listen(Port, Opts) of
        {ok, ListenSocket} ->
            io:format("  -> Listen socket created: ~p~n", [ListenSocket]),
            io:format("~n========================================~n"),
            io:format("  SERVER READY - Waiting for connections~n"),
            io:format("  Port: ~p  Mode: ~p~n", [Port, Mode]),
            io:format("========================================~n~n"),
            accept_loop(ListenSocket, 1);
        {error, Reason} ->
            io:format("  -> FAILED to listen: ~p~n", [Reason]),
            {error, Reason}
    end.

build_opts(tlcp, _Port) ->
    [
        {versions, ['tlcpv1.1']},
        {ciphers, [
            #{key_exchange => sm2_dhe, cipher => sm4_cbc, mac => sm3, prf => sm3},
            #{key_exchange => sm2, cipher => sm4_cbc, mac => sm3, prf => sm3}
        ]},
        {certs_keys, [
            #{certfile => filename:join(?CERT_DIR, "sign_chain.pem"),
              keyfile  => filename:join(?CERT_DIR, "sign.key")},
            #{certfile => filename:join(?CERT_DIR, "enc_chain.pem"),
              keyfile  => filename:join(?CERT_DIR, "enc.key")}
        ]},
        {log_level, debug},
        {reuseaddr, true}
    ];
build_opts(tls13, _Port) ->
    %% TLS 1.3 mode with SM2 — for debugging non-TLCP clients
    [
        {versions, ['tlsv1.3']},
        {ciphers, [
            #{key_exchange => any, cipher => aes_256_gcm, mac => aead, prf => sha384},
            #{key_exchange => any, cipher => aes_128_gcm, mac => aead, prf => sha256}
        ]},
        {certs_keys, [
            #{certfile => filename:join(?CERT_DIR, "sign_chain.pem"),
              keyfile  => filename:join(?CERT_DIR, "sign.key")}
        ]},
        {log_level, debug},
        {reuseaddr, true}
    ].

accept_loop(ListenSocket, ConnNum) ->
    io:format("[CONN #~p] Waiting for next client...~n", [ConnNum]),

    io:format("[CONN #~p][STEP 4] transport_accept — waiting for TCP connection...~n", [ConnNum]),
    case ssl:transport_accept(ListenSocket) of
        {ok, TransportSocket} ->
            io:format("[CONN #~p]  -> TCP connection accepted: ~p~n", [ConnNum, TransportSocket]),
            
            %% Print peer address
            case ssl:peername(TransportSocket) of
                {ok, {Addr, PeerPort}} ->
                    io:format("[CONN #~p]  -> Client address: ~p:~p~n", [ConnNum, Addr, PeerPort]);
                _ -> ok
            end,

            io:format("~n[CONN #~p][STEP 5] ssl:handshake — starting TLS/TLCP handshake...~n", [ConnNum]),
            io:format("[CONN #~p]  This is where the magic happens:~n", [ConnNum]),
            io:format("[CONN #~p]    1. ClientHello  (client -> server)~n", [ConnNum]),
            io:format("[CONN #~p]    2. ServerHello  (server -> client)~n", [ConnNum]),
            io:format("[CONN #~p]    3. Certificate  (server -> client)~n", [ConnNum]),
            io:format("[CONN #~p]    4. ServerKeyExchange (if DHE)~n", [ConnNum]),
            io:format("[CONN #~p]    5. ServerHelloDone~n", [ConnNum]),
            io:format("[CONN #~p]    6. ClientKeyExchange~n", [ConnNum]),
            io:format("[CONN #~p]    7. ChangeCipherSpec~n", [ConnNum]),
            io:format("[CONN #~p]    8. Finished~n", [ConnNum]),
            io:format("[CONN #~p]  (Debug log from OTP ssl follows below)~n~n", [ConnNum]),

            T0 = erlang:monotonic_time(millisecond),
            case ssl:handshake(TransportSocket, 30000) of
                {ok, SslSocket} ->
                    T1 = erlang:monotonic_time(millisecond),
                    io:format("~n[CONN #~p][STEP 5 DONE] Handshake SUCCESSFUL! (~p ms)~n", 
                              [ConnNum, T1 - T0]),
                    print_connection_info(ConnNum, SslSocket),
                    io:format("~n[CONN #~p][STEP 6] Entering echo loop (send data, I'll echo it back)...~n~n", 
                              [ConnNum]),
                    echo_loop(SslSocket, ConnNum);
                {error, Reason} ->
                    T1 = erlang:monotonic_time(millisecond),
                    io:format("~n[CONN #~p][STEP 5 FAILED] Handshake FAILED after ~p ms~n", 
                              [ConnNum, T1 - T0]),
                    io:format("[CONN #~p]  Reason: ~p~n", [ConnNum, Reason]),
                    io:format("[CONN #~p]  Common causes:~n", [ConnNum]),
                    io:format("[CONN #~p]    - Client doesn't support TLCP~n", [ConnNum]),
                    io:format("[CONN #~p]    - Certificate issues~n", [ConnNum]),
                    io:format("[CONN #~p]    - Cipher mismatch~n", [ConnNum]),
                    io:format("[CONN #~p]    - Version mismatch~n~n", [ConnNum])
            end,
            accept_loop(ListenSocket, ConnNum + 1);

        {error, Reason} ->
            io:format("[CONN #~p]  -> transport_accept FAILED: ~p~n", [ConnNum, Reason]),
            accept_loop(ListenSocket, ConnNum + 1)
    end.

print_connection_info(N, SslSocket) ->
    io:format("[CONN #~p]  === Connection Details ===~n", [N]),
    
    case ssl:connection_information(SslSocket) of
        {ok, Info} ->
            lists:foreach(fun
                ({protocol, V}) ->
                    io:format("[CONN #~p]    Protocol:          ~p~n", [N, V]);
                ({selected_cipher_suite, CS}) ->
                    io:format("[CONN #~p]    Cipher Suite:      ~p~n", [N, CS]);
                ({sni_hostname, SNI}) ->
                    io:format("[CONN #~p]    SNI Hostname:      ~p~n", [N, SNI]);
                ({session_id, SID}) ->
                    io:format("[CONN #~p]    Session ID:        ~p~n", [N, binary_to_list(SID)]);
                (_) -> ok
            end, Info);
        {error, _} ->
            io:format("[CONN #~p]    (could not get connection info)~n", [N])
    end,
    
    case ssl:peercert(SslSocket) of
        {ok, DerCert} ->
            io:format("[CONN #~p]    Peer Cert:         ~p bytes~n", [N, byte_size(DerCert)]);
        {error, no_peercert} ->
            io:format("[CONN #~p]    Peer Cert:         (none — no client auth)~n", [N]);
        {error, R} ->
            io:format("[CONN #~p]    Peer Cert Error:   ~p~n", [N, R])
    end,
    io:format("[CONN #~p]  =========================~n", [N]).

echo_loop(SslSocket, N) ->
    case ssl:recv(SslSocket, 0, 60000) of
        {ok, Data} ->
            io:format("[CONN #~p] Received ~p bytes: ~p~n", [N, byte_size(Data), Data]),
            ssl:send(SslSocket, Data),
            io:format("[CONN #~p] Echoed back ~p bytes~n", [N, byte_size(Data)]),
            echo_loop(SslSocket, N);
        {error, timeout} ->
            io:format("[CONN #~p] Timeout (60s) — closing connection~n", [N]),
            ssl:close(SslSocket);
        {error, closed} ->
            io:format("[CONN #~p] Connection closed by client~n~n", [N]);
        {error, Reason} ->
            io:format("[CONN #~p] Error: ~p~n~n", [N, Reason]),
            ssl:close(SslSocket)
    end.

banner(Port, Mode) ->
    io:format("~n"),
    io:format("╔══════════════════════════════════════════════════╗~n"),
    io:format("║       GMSSL/TLCP Debug Server                   ║~n"),
    io:format("║                                                  ║~n"),
    io:format("║  Port: ~-5w  Mode: ~-8w                       ║~n", [Port, Mode]),
    io:format("║                                                  ║~n"),
    io:format("║  Every handshake step will be printed.           ║~n"),
    io:format("║  log_level=debug shows OTP SSL internals.        ║~n"),
    io:format("╚══════════════════════════════════════════════════╝~n"),
    io:format("~n").
