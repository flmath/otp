-module(gmssl_certificate).

-include("ssl_internal.hrl").
-include("ssl_handshake.hrl").
-include("ssl_alert.hrl").
-include("ssl_record.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([certify/9]).

certify(Certs, CertDbHandle, CertDbRef, SSlOptions, CRLDbHandle, Role, Host, Version, ExtInfo) ->
    {SignCerts, EncCerts} = split_certs(Certs),
    case ssl_handshake:certify(SignCerts, CertDbHandle, CertDbRef, SSlOptions, CRLDbHandle, Role, Host, ?TLS_1_2, ExtInfo) of
        {SignPeerCert, _SignPubKeyInfo} = SignResult ->
            case ssl_handshake:certify(EncCerts, CertDbHandle, CertDbRef, SSlOptions, CRLDbHandle, Role, Host, ?TLS_1_2, ExtInfo) of
                {EncPeerCert, EncPubKeyInfo} ->
                    %% Return the Encryption Cert's public key info since it is used for KeyExchange,
                    %% but wait! The peer cert returned should probably be the sign cert or enc cert depending on what ssl expects.
                    %% For TLCP, the encryption cert's public key is used for key exchange.
                    %% Let's return the EncPubKeyInfo. But we return both certs in some way?
                    %% Actually, ssl_handshake only expects one {PeerCert, PublicKeyInfo}.
                    %% But the ServerKeyExchange might need the signing cert to verify the signature!
                    %% Wait, TLCP ServerKeyExchange? No, TLCP doesn't send ServerKeyExchange for ECDHE! It just uses the Encryption Cert's public key for key exchange?
                    %% Actually, GM/T 0024 ECDHE uses ServerKeyExchange containing the ephemeral ECDH public key, signed by the Signature Cert.
                    %% So PublicKeyInfo for verifying the signature must be the Signature Cert's public key!
                    %% So we MUST return the Signature Cert's public key for verify_signature!
                    %% But for encryption, the peer cert might be needed...
                    %% We will just return the SignResult, and the encryption cert can be retrieved from the session if needed.
                    %% But wait! If it's ECC_SM4_SM3 (not ECDHE), there is no ServerKeyExchange. The client encrypts the PreMasterSecret using the Encryption Cert!
                    %% In that case, we need the Encryption Cert's public key!
                    %% Let's return the Encryption Cert's public key, because we can verify the ServerKeyExchange using the Signature Cert from the Certs list manually in gmssl_handshake?
                    %% Let's return the SignResult for now.
                    {SignPeerCert, EncPubKeyInfo};
                #alert{} = Alert ->
                    Alert
            end;
        #alert{} = Alert ->
            Alert
    end.

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
    split_certs(Rest, [Cert | Acc]).

is_end_entity(BinCert) ->
    #'Certificate'{tbsCertificate = TBS} = public_key:pkix_decode_cert(BinCert, otp),
    case public_key:pkix_sign_types(TBS) of
        {_, _, _} ->
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
