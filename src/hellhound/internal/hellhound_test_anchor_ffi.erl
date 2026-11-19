%% Reusable local trust anchor for `hellhound/testing`: a P-256 root
%% constrained to loopback names, kept in a caller-chosen directory, and a
%% per-start leaf it signs. Results and errors are shaped as the Gleam types
%% in `hellhound/internal/test_pki`. Nothing here touches a system trust store.
-module(hellhound_test_anchor_ffi).
-export([load_or_create/1, replace/1, leaf/2, certificate_file/1]).

-include_lib("public_key/include/public_key.hrl").
-include_lib("kernel/include/file.hrl").

-define(CERT_FILE, <<"hellhound-root.pem">>).
-define(KEY_FILE, <<"hellhound-root-key.pem">>).
-define(ROOT_SECONDS, 90 * 86400).
-define(LEAF_SECONDS, 30 * 86400).
-define(BACKDATE, 3600).

certificate_file(Dir) -> filename:join(Dir, ?CERT_FILE).

key_file(Dir) -> filename:join(Dir, ?KEY_FILE).

%% {ok, {RootDer, RootKey}} | {error, AnchorError}
load_or_create(Dir) ->
    Cert = certificate_file(Dir),
    Key = key_file(Dir),
    case {exists(Cert), exists(Key)} of
        {false, false} -> create(Dir);
        {true, true} -> load(Cert, Key);
        {true, false} -> {error, {anchor_incomplete, Key}};
        {false, true} -> {error, {anchor_incomplete, Cert}}
    end.

%% Mint a new root and overwrite whatever the directory held.
replace(Dir) ->
    case create(Dir) of
        {ok, _} -> {ok, nil};
        {error, _} = Error -> Error
    end.

create(Dir) ->
    case ensure_dir(Dir) of
        ok ->
            {Der, Key} = mint_root(),
            KeyPem = public_key:pem_encode([public_key:pem_entry_encode('ECPrivateKey', Key)]),
            CertPem = public_key:pem_encode([{'Certificate', Der, not_encrypted}]),
            %% The key goes first: a directory with a key and no certificate
            %% is reported as incomplete, never regenerated.
            case write_file(key_file(Dir), KeyPem, 8#600) of
                ok ->
                    case write_file(certificate_file(Dir), CertPem, 8#644) of
                        ok -> {ok, {Der, Key}};
                        Error -> Error
                    end;
                Error -> Error
            end;
        error ->
            {error, {anchor_write_failed, Dir}}
    end.

exists(Path) ->
    case file:read_file_info(Path) of
        {error, enoent} -> false;
        _ -> true
    end.

%% A directory this creates is owner-only; an existing one is the caller's.
ensure_dir(Dir) ->
    case file:read_file_info(Dir) of
        {ok, #file_info{type = directory}} -> ok;
        {ok, _} -> error;
        {error, enoent} ->
            case filelib:ensure_path(filename:dirname(Dir)) of
                ok ->
                    case file:make_dir(Dir) of
                        ok -> ok_or_error(file:change_mode(Dir, 8#700));
                        _ -> error
                    end;
                _ -> error
            end;
        _ -> error
    end.

ok_or_error(ok) -> ok;
ok_or_error(_) -> error.

%% Write through a temporary file whose mode is set before any content is
%% written, then rename it over the final path.
write_file(Path, Contents, Mode) ->
    Tmp = <<Path/binary, ".tmp">>,
    _ = file:delete(Tmp),
    Result =
        case file:open(Tmp, [write, exclusive, binary, raw]) of
            {ok, Io} ->
                Written =
                    case file:change_mode(Tmp, Mode) of
                        ok ->
                            case file:write(Io, Contents) of
                                ok -> file:sync(Io);
                                E -> E
                            end;
                        E -> E
                    end,
                _ = file:close(Io),
                case Written of
                    ok -> file:rename(Tmp, Path);
                    E2 -> E2
                end;
            E -> E
        end,
    case Result of
        ok -> ok;
        _ ->
            _ = file:delete(Tmp),
            {error, {anchor_write_failed, Path}}
    end.

load(CertPath, KeyPath) ->
    case file:read_file_info(KeyPath) of
        {ok, #file_info{mode = Mode}} when Mode band 8#077 =/= 0 ->
            {error, {anchor_key_exposed, KeyPath}};
        {ok, _} ->
            case {file:read_file(CertPath), file:read_file(KeyPath)} of
                {{ok, CertPem}, {ok, KeyPem}} -> check(CertPath, CertPem, KeyPath, KeyPem);
                {{error, _}, _} -> {error, {anchor_unreadable, CertPath}};
                {_, {error, _}} -> {error, {anchor_unreadable, KeyPath}}
            end;
        {error, _} ->
            {error, {anchor_unreadable, KeyPath}}
    end.

check(CertPath, CertPem, KeyPath, KeyPem) ->
    case {decode_cert(CertPem), decode_key(KeyPem)} of
        {error, _} -> {error, {anchor_corrupt, CertPath}};
        {_, error} -> {error, {anchor_corrupt, KeyPath}};
        {{ok, Der, Cert}, {ok, Key}} ->
            case is_our_root(Der, Cert, Key) of
                false -> {error, anchor_mismatch};
                true ->
                    case is_current(Cert) of
                        true -> {ok, {Der, Key}};
                        false -> {error, anchor_expired}
                    end
            end
    end.

decode_cert(Pem) ->
    try public_key:pem_decode(Pem) of
        [{'Certificate', Der, not_encrypted}] ->
            {ok, Der, public_key:pkix_decode_cert(Der, otp)};
        _ -> error
    catch _:_ -> error
    end.

decode_key(Pem) ->
    try public_key:pem_decode(Pem) of
        [{'ECPrivateKey', _, not_encrypted} = Entry] ->
            case public_key:pem_entry_decode(Entry) of
                #'ECPrivateKey'{parameters = {namedCurve, ?secp256r1}} = Key -> {ok, Key};
                _ -> error
            end;
        _ -> error
    catch _:_ -> error
    end.

%% The key signs the certificate, and the certificate is a self-signed root
%% with exactly the loopback constraints this module mints.
is_our_root(Der, #'OTPCertificate'{tbsCertificate = Tbs}, #'ECPrivateKey'{publicKey = Point}) ->
    #'OTPTBSCertificate'{subjectPublicKeyInfo = Spki, extensions = Exts,
                         issuer = Issuer, subject = Subject} = Tbs,
    case Spki of
        #'OTPSubjectPublicKeyInfo'{subjectPublicKey = #'ECPoint'{point = Point}} ->
            Issuer =:= Subject
                andalso public_key:pkix_verify(Der, {#'ECPoint'{point = Point},
                                                     {namedCurve, ?secp256r1}})
                andalso lists:member(name_constraints(), Exts)
                andalso lists:member(basic_constraints(), Exts);
        _ -> false
    end.

is_current(#'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{validity = V}}) ->
    #'Validity'{notBefore = From, notAfter = To} = V,
    Now = now_seconds(),
    seconds(From) =< Now andalso Now =< seconds(To).

leaf(RootDer, RootKey) ->
    #'OTPCertificate'{tbsCertificate = Root} = public_key:pkix_decode_cert(RootDer, otp),
    #'Validity'{notAfter = RootEnd} = Root#'OTPTBSCertificate'.validity,
    Now = now_seconds(),
    Until = min(seconds(RootEnd), Now + ?LEAF_SECONDS),
    Key = public_key:generate_key({namedCurve, ?secp256r1}),
    #'ECPrivateKey'{publicKey = Point} = Key,
    #'ECPrivateKey'{publicKey = RootPoint} = RootKey,
    Tbs = #'OTPTBSCertificate'{
             version = v3,
             serialNumber = serial(),
             signature = signature(),
             issuer = Root#'OTPTBSCertificate'.subject,
             validity = #'Validity'{notBefore = time(Now - ?BACKDATE), notAfter = time(Until)},
             subject = name([{?'id-at-commonName', <<"localhost">>}]),
             subjectPublicKeyInfo = spki(Point),
             extensions =
                 [#'Extension'{extnID = ?'id-ce-basicConstraints', critical = true,
                               extnValue = #'BasicConstraints'{cA = false,
                                                               pathLenConstraint = asn1_NOVALUE}},
                  #'Extension'{extnID = ?'id-ce-keyUsage', critical = true,
                               extnValue = [digitalSignature]},
                  #'Extension'{extnID = ?'id-ce-extKeyUsage', critical = false,
                               extnValue = [?'id-kp-serverAuth']},
                  #'Extension'{extnID = ?'id-ce-subjectAltName', critical = false,
                               extnValue = [{dNSName, "localhost"},
                                            {iPAddress, <<127, 0, 0, 1>>}]},
                  #'Extension'{extnID = ?'id-ce-authorityKeyIdentifier', critical = false,
                               extnValue = #'AuthorityKeyIdentifier'{
                                              keyIdentifier = key_id(RootPoint),
                                              authorityCertIssuer = asn1_NOVALUE,
                                              authorityCertSerialNumber = asn1_NOVALUE}}]},
    Der = public_key:pkix_sign(Tbs, RootKey),
    {Der, {'ECPrivateKey', public_key:der_encode('ECPrivateKey', Key)}}.

mint_root() ->
    Key = public_key:generate_key({namedCurve, ?secp256r1}),
    #'ECPrivateKey'{publicKey = Point} = Key,
    Now = now_seconds(),
    Subject = name([{?'id-at-organizationName', <<"Hellhound testing">>},
                    {?'id-at-commonName', <<"Hellhound local development root">>}]),
    Tbs = #'OTPTBSCertificate'{
             version = v3,
             serialNumber = serial(),
             signature = signature(),
             issuer = Subject,
             validity = #'Validity'{notBefore = time(Now - ?BACKDATE),
                                    notAfter = time(Now + ?ROOT_SECONDS)},
             subject = Subject,
             subjectPublicKeyInfo = spki(Point),
             extensions =
                 [basic_constraints(),
                  #'Extension'{extnID = ?'id-ce-keyUsage', critical = true,
                               extnValue = [keyCertSign, cRLSign]},
                  name_constraints(),
                  #'Extension'{extnID = ?'id-ce-subjectKeyIdentifier', critical = false,
                               extnValue = key_id(Point)}]},
    {public_key:pkix_sign(Tbs, Key), Key}.

basic_constraints() ->
    #'Extension'{extnID = ?'id-ce-basicConstraints', critical = true,
                 extnValue = #'BasicConstraints'{cA = true, pathLenConstraint = 0}}.

%% The root may only certify loopback names: `localhost` (and, by DNS name
%% constraint semantics, names under it), 127.0.0.1/32 and ::1/128.
name_constraints() ->
    Subtree = fun(Base) -> #'GeneralSubtree'{base = Base, minimum = 0, maximum = asn1_NOVALUE} end,
    #'Extension'{extnID = ?'id-ce-nameConstraints', critical = true,
                 extnValue = #'NameConstraints'{
                                permittedSubtrees =
                                    [Subtree({dNSName, "localhost"}),
                                     Subtree({iPAddress, <<127, 0, 0, 1, 255, 255, 255, 255>>}),
                                     Subtree({iPAddress, <<0:120, 1:8, (1 bsl 128 - 1):128>>})],
                                excludedSubtrees = asn1_NOVALUE}}.

signature() ->
    #'SignatureAlgorithm'{algorithm = ?'ecdsa-with-SHA256', parameters = asn1_NOVALUE}.

spki(Point) ->
    #'OTPSubjectPublicKeyInfo'{
       algorithm = #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey',
                                         parameters = {namedCurve, ?secp256r1}},
       subjectPublicKey = #'ECPoint'{point = Point}}.

name(Attributes) ->
    {rdnSequence, [[#'AttributeTypeAndValue'{type = Type, value = {utf8String, Value}}]
                   || {Type, Value} <- Attributes]}.

key_id(Point) -> crypto:hash(sha, Point).

%% A random positive 127-bit serial, so a replaced root or a new leaf never
%% repeats an issuer and serial pair a browser has seen.
serial() ->
    <<S:128>> = crypto:strong_rand_bytes(16),
    (S bsr 1) bor 1.

now_seconds() ->
    calendar:datetime_to_gregorian_seconds(calendar:universal_time()).

time(Seconds) ->
    {{Y, Mo, D}, {H, Mi, S}} = calendar:gregorian_seconds_to_datetime(Seconds),
    case Y < 2050 of
        true ->
            {utcTime, lists:flatten(io_lib:format("~2..0b~2..0b~2..0b~2..0b~2..0b~2..0bZ",
                                                  [Y rem 100, Mo, D, H, Mi, S]))};
        false ->
            {generalTime, lists:flatten(io_lib:format("~4..0b~2..0b~2..0b~2..0b~2..0b~2..0bZ",
                                                      [Y, Mo, D, H, Mi, S]))}
    end.

seconds({utcTime, [Y1, Y2 | Rest]}) ->
    Year = list_to_integer([Y1, Y2]),
    Century = case Year >= 50 of true -> 1900; false -> 2000 end,
    seconds({generalTime, integer_to_list(Century + Year) ++ Rest});
seconds({generalTime, [Y1, Y2, Y3, Y4, M1, M2, D1, D2, H1, H2, I1, I2, S1, S2, $Z]}) ->
    calendar:datetime_to_gregorian_seconds(
      {{list_to_integer([Y1, Y2, Y3, Y4]), list_to_integer([M1, M2]), list_to_integer([D1, D2])},
       {list_to_integer([H1, H2]), list_to_integer([I1, I2]), list_to_integer([S1, S2])}});
seconds(_) ->
    0.
