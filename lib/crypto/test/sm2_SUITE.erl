-module(sm2_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-include_lib("common_test/include/ct.hrl").

all() ->
    [sm2_sign_verify].

init_per_suite(Config) ->
    case crypto:supports(curves) of
        Curves ->
            case lists:member(sm2, Curves) of
                true -> Config;
                false -> {skip, "sm2 curve not supported by OpenSSL"}
            end
    end.

end_per_suite(_Config) ->
    ok.

sm2_sign_verify(_Config) ->
    {PubKey, PrivKey} = crypto:generate_key(ecdh, sm2),
    Msg = <<"Hello SM2 World">>,
    Sig = crypto:sign(sm2, sm3, Msg, [PrivKey, sm2]),
    true = crypto:verify(sm2, sm3, Msg, Sig, [PubKey, sm2]),
    false = crypto:verify(sm2, sm3, <<"Wrong">>, Sig, [PubKey, sm2]),
    ok.
