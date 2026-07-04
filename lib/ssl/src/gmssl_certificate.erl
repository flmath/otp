-module(gmssl_certificate).

-include("ssl_internal.hrl").
-include("ssl_handshake.hrl").
-include("ssl_alert.hrl").
-include("ssl_record.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([certify/9]).

certify(Certs, _CertDbHandle, _CertDbRef, _SSlOptions, _CRLDbHandle, _Role, _Host, _Version, _ExtInfo) ->
    {SignCerts, EncCerts} = split_certs(Certs),
    SignResult = extract_cert_info(SignCerts),
    if EncCerts == [] ->
           SignResult;
       true ->
           {_EncPeerCert, EncPubKeyInfo} = extract_cert_info(EncCerts),
           {PeerCert, _} = SignResult,
           {PeerCert, EncPubKeyInfo}
    end.

extract_cert_info([#cert{otp = OTPCert} = PeerCert | _]) ->
    #'OTPCertificate'{tbsCertificate = TBS} = OTPCert,
    #'OTPSubjectPublicKeyInfo'{algorithm = AlgInfo, subjectPublicKey = PubKey} = TBS#'OTPTBSCertificate'.subjectPublicKeyInfo,
    #'PublicKeyAlgorithm'{algorithm = AlgOid, parameters = Params} = AlgInfo,
    PublicKeyInfo = {AlgOid, PubKey, Params},
    {PeerCert, PublicKeyInfo}.

split_certs(Certs) ->
    split_certs(Certs, []).

split_certs([Cert | Rest], Acc) when length(Acc) > 0 ->
    %% Check if this is the start of the encryption chain
    %% We can check if it's an end-entity cert (cA = false or no basic constraints)
    case is_end_entity(Cert) of
        true ->
            %% Found the second chain
            {lists:reverse(Acc), [Cert | Rest]};
        false ->
            split_certs(Rest, [Cert | Acc])
    end;
split_certs([Cert | Rest], Acc) ->
    split_certs(Rest, [Cert | Acc]);
split_certs([], Acc) ->
    {lists:reverse(Acc), []}.

is_end_entity(#cert{otp = OTPCert}) ->
    #'OTPCertificate'{tbsCertificate = TBS} = OTPCert,
    #'SignatureAlgorithm'{algorithm = AlgId} = TBS#'OTPTBSCertificate'.signature,
    case public_key:pkix_sign_types(AlgId) of
        _ ->
            %% Let's check basic constraints
            Extensions = TBS#'OTPTBSCertificate'.extensions,
            case get_extension(?'id-ce-basicConstraints', Extensions) of
                #'Extension'{extnValue = #'BasicConstraints'{cA = true}} -> false;
                _ -> true
            end
    end.

get_extension(_, asn1_NOVALUE) -> undefined;
get_extension(_, []) -> undefined;
get_extension(Id, [#'Extension'{extnID = Id} = Ext | _]) -> Ext;
get_extension(Id, [_ | Rest]) -> get_extension(Id, Rest).
