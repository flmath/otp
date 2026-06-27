-module(sm2_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-include_lib("common_test/include/ct.hrl").

all() ->
    [sm2_sign_verify,
     sm2_encrypt_decrypt].

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

sm2_encrypt_decrypt(_Config) ->
    {PubKey, PrivKey} = crypto:generate_key(ecdh, sm2),
    Msg = <<"Secret Premaster Data">>,
    
    %% Public Encrypt
    Cipher = crypto:public_encrypt(sm2, Msg, [PubKey, sm2], []),
    
    %% The ciphertext must not be the same as the plaintext
    true = (Cipher =/= Msg),
    
    %% Private Decrypt
    Plain = crypto:private_decrypt(sm2, Cipher, [PrivKey, sm2], []),
    Msg = Plain,
    
    %% Negative Test
    BadCipher = <<Cipher/binary, "bad">>,
    try crypto:private_decrypt(sm2, BadCipher, [PrivKey, sm2], []) of
        _ -> ct:fail("Expected decryption to fail")
    catch
        error:_ -> ok
    end,
    ok.
