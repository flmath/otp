-module(gmssl_record).

-include("gmssl_internal.hrl").

-export([protocol_version/1, protocol_version_name/1, lowest_protocol_version/1, lowest_protocol_version/2,
	 highest_protocol_version/1, highest_protocol_version/2,
	 is_higher/2, supported_protocol_versions/0,
	 is_acceptable_version/2, hello_version/2]).

-export_type([gmssl_atom_version/0]).

-type gmssl_atom_version()  :: 'tlcpv1.1'.

%% Protocol version handling

protocol_version_name('tlcpv1.1') ->
    ?TLCP_1_1.

protocol_version(?TLCP_1_1) ->
    'tlcpv1.1'.

lowest_protocol_version(Version1, Version2) when Version1 < Version2 ->
    Version1;
lowest_protocol_version(_, Version2) ->
    Version2.

lowest_protocol_version(Versions) ->
    check_protocol_version(Versions, fun lowest_protocol_version/2).

highest_protocol_version(Versions) ->
    check_protocol_version(Versions, fun highest_protocol_version/2).

highest_protocol_version(Version1, Version2) when Version1 > Version2 ->
    Version1;
highest_protocol_version(_, Version2) ->
    Version2.

is_higher(V1, V2) -> 
    V1 > V2.

is_acceptable_version(Version, Versions) ->
    lists:member(Version, Versions).

hello_version(Versions, _) ->
    highest_protocol_version(Versions).

supported_protocol_versions() ->
    ['tlcpv1.1'].

check_protocol_version([Version], _F) ->
    Version;
check_protocol_version([Version | Versions], F) ->
    F(Version, check_protocol_version(Versions, F)).
