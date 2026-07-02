-module(gmssl_handshake).

-include("gmssl_internal.hrl").

-export([prf/5, master_secret/4]).

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
