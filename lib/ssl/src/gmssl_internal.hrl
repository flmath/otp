-ifndef(gmssl_internal).
-define(gmssl_internal, true).

%% Protocol versions
-define(TLCP_1_1, {1,1}).

%% Cipher suites
-define(ECC_SM4_SM3, <<16#E0, 16#13>>).
-define(ECDHE_SM4_SM3, <<16#E0, 16#11>>).

-endif.
