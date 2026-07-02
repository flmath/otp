-module(gmssl_handshake_SUITE).
-compile(export_all).
-include_lib("common_test/include/ct.hrl").
-include("gmssl_internal.hrl").

all() ->
    [master_secret].

master_secret(_Config) ->
    PremasterSecret = <<"123456789012345678901234567890123456789012345678">>,
    ClientRandom = <<"client_random_32_bytes_long_12345">>,
    ServerRandom = <<"server_random_32_bytes_long_12345">>,
    {ok, MasterSecret} = gmssl_handshake:master_secret(?TLCP_1_1, PremasterSecret, ClientRandom, ServerRandom),
    48 = byte_size(MasterSecret),
    ok.
