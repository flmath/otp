-module(crypto_gmssl_SUITE).
-compile(export_all).
-include_lib("common_test/include/ct.hrl").

suite() ->
    [{timetrap, {minutes, 1}}].

all() ->
    [test_legacy_openssl, test_gmssl_sm3, test_gmssl_sm4, test_gmssl_sm2].

init_per_suite(Config) ->
    %% Ensure crypto is started
    application:start(crypto),
    Config.

end_per_suite(_Config) ->
    application:stop(crypto),
    ok.

test_legacy_openssl(_Config) ->
    %% Ensure gmssl_mode is false (the default)
    application:set_env(crypto, gmssl_mode, false),
    
    %% Reload the module to pick up the OpenSSL NIF
    code:purge(crypto),
    code:load_file(crypto),
    
    %% This should work via OpenSSL
    Info = crypto:info_lib(),
    ct:log("Legacy Info: ~p", [Info]),
    
    %% A basic hash should work
    Hash = crypto:hash(sha256, <<"hello">>),
    true = is_binary(Hash),
    ok.

test_gmssl_sm3(_Config) ->
    %% Ensure we are using gmssl_crypto (not standard crypto)
    application:set_env(crypto, gmssl_mode, true),
    code:purge(crypto),
    code:load_file(crypto),
    
    %% Compute SM3 Hash
    Data = <<"hello">>,
    Hash = crypto:hash(sm3, Data),
    %% Known answer for SM3("hello")
    Expected = <<16#be, 16#cb, 16#bf, 16#aa, 16#e6, 16#54, 16#8b, 16#8b,
                 16#f0, 16#cf, 16#ca, 16#d5, 16#a2, 16#71, 16#83, 16#cd,
                 16#1b, 16#e6, 16#09, 16#3b, 16#1c, 16#ce, 16#cc, 16#c3,
                 16#03, 16#d9, 16#c6, 16#1d, 16#0a, 16#64, 16#52, 16#68>>,
    Expected = Hash,
    ct:log("SM3 hash of 'hello' correctly computed via gmssl: ~p", [Hash]),
    
    %% Unimplemented algorithms should throw an exception from our stub
    try crypto:hash(sha256, <<"hello">>) of
        _ -> ct:fail("Expected exception for unimplemented SHA256")
    catch
        error:_ ->
            ct:log("SHA256 correctly threw an exception in gmssl mode!"),
            ok
    end,
    ok.

test_gmssl_sm4(_Config) ->
    application:set_env(crypto, gmssl_mode, true),
    code:purge(crypto),
    code:load_file(crypto),

    Key = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16>>,
    IV = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16>>,
    Data = <<"hello world data">>,
    
    %% Encrypt
    Ciphertext = crypto:crypto_one_time(sm4_cbc, Key, IV, Data, true),
    
    %% Decrypt
    Decrypted = crypto:crypto_one_time(sm4_cbc, Key, IV, Ciphertext, false),
    
    Data = Decrypted,
    ok.

test_gmssl_sm2(_Config) ->
    application:set_env(crypto, gmssl_mode, true),
    code:purge(crypto),
    code:load_file(crypto),

    Priv = <<188, 80, 88, 253, 107, 229, 238, 185, 122, 174, 180, 24, 127, 93, 81, 35, 189, 241, 209, 179, 38, 142, 138, 132, 80, 72, 92, 143, 79, 143, 30, 69>>,
    Pub = <<4, 152, 194, 37, 44, 212, 173, 35, 30, 75, 3, 141, 161, 110, 222, 67, 242, 156, 133, 146, 55, 254, 87, 90, 210, 179, 122, 107, 104, 163, 9, 94, 190, 60, 107, 90, 169, 248, 207, 181, 210, 45, 73, 137, 127, 76, 42, 89, 242, 255, 181, 45, 144, 195, 19, 199, 36, 16, 183, 23, 68, 204, 49, 167, 130>>,
    
    Data = <<"Sign me up for SM2!">>,
    
    %% Sign
    Sig = crypto:sign(sm2, sm3, Data, [Priv, sm2]),
    
    %% Verify
    true = crypto:verify(sm2, sm3, Data, Sig, [Pub, sm2]),
    
    %% Verify fails on bad data
    false = crypto:verify(sm2, sm3, <<"Bad data">>, Sig, [Pub, sm2]),
    
    %% Generate a fresh SM2 keypair
    {NewPub, NewPriv} = crypto:generate_key(ecdh, sm2),
    
    %% Sign and verify with the new keypair
    NewSig = crypto:sign(sm2, sm3, Data, [NewPriv, sm2]),
    true = crypto:verify(sm2, sm3, Data, NewSig, [NewPub, sm2]),
    
    %% Compute shared secret using ECDH
    {AlicePub, AlicePriv} = crypto:generate_key(ecdh, sm2),
    {BobPub, BobPriv} = crypto:generate_key(ecdh, sm2),
    
    AliceSecret = crypto:compute_key(ecdh, BobPub, AlicePriv, sm2),
    BobSecret = crypto:compute_key(ecdh, AlicePub, BobPriv, sm2),
    
    AliceSecret = BobSecret,
    
    ok.
