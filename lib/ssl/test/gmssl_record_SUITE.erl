-module(gmssl_record_SUITE).
-compile(export_all).
-include_lib("common_test/include/ct.hrl").

all() ->
    [versions].

versions(_Config) ->
    {1, 1} = gmssl_record:protocol_version_name('tlcpv1.1'),
    'tlcpv1.1' = gmssl_record:protocol_version({1, 1}),
    ['tlcpv1.1'] = gmssl_record:supported_protocol_versions(),
    {1, 1} = gmssl_record:lowest_protocol_version([{1, 1}]),
    {1, 1} = gmssl_record:highest_protocol_version([{1, 1}]),
    ok.
