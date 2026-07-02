%%% @doc TLCP/GMSSL Debug Client (Erlang)
%%%
%%% Mock client for testing the Erlang TLCP server.
%%% Prints every step of the connection process with timing info.
%%%
%%% Usage:
%%%   client:start().             %% Connect to localhost:8443 TLCP
%%%   client:start(8443).         %% Custom port
%%%   client:start(8443, tlcp).   %% Explicit mode
%%%   client:start(8443, tls13).  %% TLS 1.3 mode
%%%
-module(client).
-export([start/0, start/1, start/2]).

-define(CERT_DIR, "certs").

start() -> start(8443).
start(Port) -> start(Port, tlcp).
start(Port, Mode) ->
    io:format("~n"),
    io:format("======================================~n"),
    io:format("  GMSSL/TLCP Debug Client~n"),
    io:format("  Target: localhost:~p  Mode: ~p~n", [Port, Mode]),
    io:format("======================================~n~n"),

    io:format("[STEP 1] Starting SSL application...~n"),
    ssl:start(),
    io:format("  -> OK~n"),

    io:format("~n[STEP 2] Building connection options...~n"),
    Opts = build_opts(Mode),
    io:format("  -> Options ready~n"),

    io:format("~n[STEP 3] Connecting to localhost:~p...~n", [Port]),
    T0 = erlang:monotonic_time(millisecond),
    case ssl:connect("localhost", Port, Opts, 10000) of
        {ok, SslSocket} ->
            T1 = erlang:monotonic_time(millisecond),
            io:format("  -> Connected! Handshake completed in ~p ms~n", [T1 - T0]),
            print_connection_info(SslSocket),

            io:format("~n[STEP 4] Sending test message...~n"),
            TestMsg = <<"Hello from Erlang TLCP client!">>,
            ssl:send(SslSocket, TestMsg),
            io:format("  -> Sent: ~p~n", [TestMsg]),

            io:format("~n[STEP 5] Waiting for echo response...~n"),
            case ssl:recv(SslSocket, 0, 5000) of
                {ok, Data} ->
                    io:format("  -> Received: ~p~n", [Data]),
                    case Data =:= TestMsg of
                        true  -> io:format("  -> Echo MATCH! Server echoed correctly.~n");
                        false -> io:format("  -> Echo MISMATCH! Expected ~p~n", [TestMsg])
                    end;
                {error, Reason} ->
                    io:format("  -> Receive error: ~p~n", [Reason])
            end,

            io:format("~n[STEP 6] Closing connection...~n"),
            ssl:close(SslSocket),
            io:format("  -> Connection closed.~n~n"),
            ok;

        {error, Reason} ->
            T1 = erlang:monotonic_time(millisecond),
            io:format("  -> Connection FAILED after ~p ms~n", [T1 - T0]),
            io:format("  -> Reason: ~p~n", [Reason]),
            io:format("~n  Troubleshooting:~n"),
            io:format("    - Is the server running? (./run_server.sh)~n"),
            io:format("    - Is the port correct? (~p)~n", [Port]),
            io:format("    - Were certificates generated? (./generate_certs.sh)~n~n"),
            {error, Reason}
    end.

build_opts(tlcp) ->
    [
        {versions, ['tlcpv1.1']},
        {ciphers, [
            #{key_exchange => sm2_dhe, cipher => sm4_cbc, mac => sm3, prf => sm3},
            #{key_exchange => sm2, cipher => sm4_cbc, mac => sm3, prf => sm3}
        ]},
        {cacertfile, filename:join(?CERT_DIR, "rootca.crt")},
        {verify, verify_peer},
        {log_level, debug}
    ];
build_opts(tls13) ->
    [
        {versions, ['tlsv1.3']},
        {ciphers, [
            #{key_exchange => any, cipher => aes_256_gcm, mac => aead, prf => sha384},
            #{key_exchange => any, cipher => aes_128_gcm, mac => aead, prf => sha256}
        ]},
        {cacertfile, filename:join(?CERT_DIR, "rootca.crt")},
        {verify, verify_peer},
        {log_level, debug}
    ].

print_connection_info(SslSocket) ->
    io:format("~n  === Connection Details ===~n"),
    case ssl:connection_information(SslSocket) of
        {ok, Info} ->
            lists:foreach(fun
                ({protocol, V}) ->
                    io:format("    Protocol:     ~p~n", [V]);
                ({selected_cipher_suite, CS}) ->
                    io:format("    Cipher Suite: ~p~n", [CS]);
                ({sni_hostname, SNI}) ->
                    io:format("    SNI:          ~p~n", [SNI]);
                (_) -> ok
            end, Info);
        _ -> ok
    end,
    case ssl:peercert(SslSocket) of
        {ok, DerCert} ->
            io:format("    Server Cert:  ~p bytes~n", [byte_size(DerCert)]);
        _ -> ok
    end,
    io:format("  =========================~n").
