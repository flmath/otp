-module(tlcp_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-include_lib("common_test/include/ct.hrl").

all() ->
    [tlcp_dispatch].

init_per_suite(Config) ->
    application:start(crypto),
    application:start(asn1),
    application:start(public_key),
    application:start(ssl),
    Config.

end_per_suite(_Config) ->
    application:stop(ssl),
    application:stop(public_key),
    application:stop(asn1),
    application:stop(crypto),
    ok.

tlcp_dispatch(_Config) ->
    %% We just test that the SSL router dispatches correctly to the TLCP modules
    %% Since we just duplicated the TLS 1.2 modules as stubs, the connection will likely 
    %% fail with an internal error or timeout when trying to actually execute a full TLCP handshake,
    %% but we can check that it doesn't fail with {error, {options, {versions, ...}}}.
    
    Opts = [{versions, ['tlcpv1.1']}],
    
    %% Attempt to listen using TLCP version
    case ssl:listen(0, Opts) of
        {ok, ListenSocket} ->
            ssl:close(ListenSocket),
            ok;
        {error, no_cipher_suites} ->
            %% This is also a valid response from the tlcp_server_connection 
            %% because we haven't defined any TLCP cipher suites yet!
            ok;
        {error, eoptions} ->
            ct:fail("TLCP version not recognized by ssl router")
    end.
