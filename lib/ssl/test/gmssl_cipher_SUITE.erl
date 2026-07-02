-module(gmssl_cipher_SUITE).
-compile(export_all).
-include_lib("common_test/include/ct.hrl").
-include("gmssl_internal.hrl").

all() ->
    [mappings].

mappings(_Config) ->
    Map1 = #{key_exchange => sm2, cipher => sm4_cbc, mac => sm3, prf => sm3},
    Map2 = #{key_exchange => sm2_dhe, cipher => sm4_cbc, mac => sm3, prf => sm3},
    Map1 = gmssl_cipher:suite_bin_to_map(?ECC_SM4_SM3),
    Map2 = gmssl_cipher:suite_bin_to_map(?ECDHE_SM4_SM3),
    ?ECC_SM4_SM3 = gmssl_cipher:suite_map_to_bin(Map1),
    ?ECDHE_SM4_SM3 = gmssl_cipher:suite_map_to_bin(Map2),
    [?ECC_SM4_SM3, ?ECDHE_SM4_SM3] = gmssl_cipher:suites('tlcpv1.1'),
    ok.
