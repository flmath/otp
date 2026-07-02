-module(gmssl_handshake).

-include("gmssl_internal.hrl").

-export([prf/5, master_secret/4, setup_keys/8, finished/4, certificate_verify/2]).

-spec finished(client | server, ssl:prf_alg(), binary(), [binary()]) -> binary().
finished(Role, PrfAlgo, MasterSecret, Handshake) ->
    %% TLCP finished verify_data:
    %% PRF(master_secret, finished_label, Hash(handshake_messages))
    Hash = crypto:hash(mac_algo(PrfAlgo), Handshake),
    {ok, Bin} = prf(PrfAlgo, MasterSecret, finished_label(Role), Hash, 12),
    Bin.

finished_label(client) -> "client finished";
finished_label(server) -> "server finished".

mac_algo(Alg) when is_atom(Alg) -> Alg;
mac_algo(_) -> sm3.

-spec certificate_verify(ssl:hash(), [binary()]) -> binary().
certificate_verify(HashAlgo, Handshake) ->
    %% TLCP Certificate Verify uses SM3 hash over handshake messages
    crypto:hash(HashAlgo, Handshake).

-spec prf(ssl:mac_alg(), binary(), string(), [binary()], non_neg_integer()) ->
          {ok, binary()} | {error, any()}.
prf(sm3, Secret, Label, Seed, WantedLength) ->
    %% TLCP uses SM3 for PRF. The PRF is defined as:
    %% PRF(Secret, label, seed) = P_SM3(Secret, label + seed)
    %% P_SM3(secret, seed) = HMAC_SM3(secret, A(1) + seed) + HMAC_SM3(secret, A(2) + seed) + ...
    %% This is identical to TLS 1.2 PRF but with SM3.
    %% The tls_v1:prf handles this natively if the MAC is supported.
    try tls_v1:prf(sm3, Secret, Label, Seed, WantedLength) of
        Result -> {ok, Result}
    catch
        error:Reason -> {error, Reason}
    end;
prf(_, _, _, _, _) ->
    {error, unsupported_mac}.

-spec master_secret(ssl_record:ssl_version(), binary(), binary(), binary()) ->
          {ok, binary()} | {error, any()}.
master_secret(?TLCP_1_1, PremasterSecret, ClientRandom, ServerRandom) ->
    %% TLCP Master Secret calculation
    prf(sm3, PremasterSecret, "master secret", [ClientRandom, ServerRandom], 48);
master_secret(_, _, _, _) ->
    {error, unsupported_version}.

-spec setup_keys(ssl_record:ssl_version(), ssl:prf_alg(), binary(),
                 binary(), binary(), non_neg_integer(),
                 non_neg_integer(), non_neg_integer()) ->
          {binary(), binary(), binary(), binary(), binary(), binary()}.
setup_keys(?TLCP_1_1, PrfAlgo, MasterSecret, ServerRandom, ClientRandom, HashSize, KML, IVS) ->
    %% TLCP uses the same key expansion as TLS 1.2 but with SM3.
    %% key_block = PRF(SecurityParameters.master_secret,
    %%                 "key expansion",
    %%                 SecurityParameters.server_random + SecurityParameters.client_random)
    {ok, KeyBlock} = prf(PrfAlgo, MasterSecret, "key expansion",
                         [ServerRandom, ClientRandom],
                         2 * HashSize + 2 * KML + 2 * IVS),
    <<ClientWriteMacSecret:HashSize/binary,
      ServerWriteMacSecret:HashSize/binary,
      ClientWriteKey:KML/binary,
      ServerWriteKey:KML/binary,
      ClientIV:IVS/binary,
      ServerIV:IVS/binary>> = KeyBlock,
    {ClientWriteMacSecret, ServerWriteMacSecret, ClientWriteKey,
     ServerWriteKey, ClientIV, ServerIV}.
