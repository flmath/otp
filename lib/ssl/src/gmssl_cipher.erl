-module(gmssl_cipher).

-include("gmssl_internal.hrl").

-export([suite_bin_to_map/1, suite_map_to_bin/1, suites/1]).

-spec suite_bin_to_map(binary()) -> map() | error.
suite_bin_to_map(?ECC_SM4_SM3) ->
    #{key_exchange => sm2,
      cipher => sm4_cbc,
      mac => sm3,
      prf => sm3};
suite_bin_to_map(?ECDHE_SM4_SM3) ->
    #{key_exchange => sm2_dhe,
      cipher => sm4_cbc,
      mac => sm3,
      prf => sm3};
suite_bin_to_map(_) ->
    error.

-spec suite_map_to_bin(map()) -> binary() | error.
suite_map_to_bin(#{key_exchange := sm2, cipher := sm4_cbc, mac := sm3, prf := sm3}) ->
    ?ECC_SM4_SM3;
suite_map_to_bin(#{key_exchange := sm2_dhe, cipher := sm4_cbc, mac := sm3, prf := sm3}) ->
    ?ECDHE_SM4_SM3;
suite_map_to_bin(_) ->
    error.

-spec suites(gmssl_record:gmssl_atom_version()) -> [binary()].
suites('tlcpv1.1') ->
    [?ECC_SM4_SM3, ?ECDHE_SM4_SM3].
