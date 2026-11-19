%% Test-only helpers for the reusable local trust anchor: temporary
%% directories, file modes, and independent inspection of the root with OTP's
%% own public_key.
-module(hellhound_anchor_test_ffi).
-export([fresh_dir/0, mode/1, set_mode/2, write/2, read/1, delete/1,
         copy/2, root_shape/1, foreign_leaf_validation/1, expire/1,
         os_process_roots/2, swap_scalar/1, resign/2]).

-include_lib("public_key/include/public_key.hrl").
-include_lib("kernel/include/file.hrl").

fresh_dir() ->
    Suffix = binary:encode_hex(crypto:strong_rand_bytes(8)),
    Dir = filename:join([<<"build">>, <<"anchor-tests">>, Suffix]),
    %% Creates Dir's parent only; Dir itself does not exist yet.
    ok = filelib:ensure_dir(Dir),
    Dir.

mode(Path) ->
    {ok, Info} = file:read_file_info(Path),
    Info#file_info.mode band 8#777.

set_mode(Path, Mode) ->
    ok = file:change_mode(Path, Mode),
    nil.

write(Path, Bin) ->
    ok = file:write_file(Path, Bin),
    nil.

read(Path) ->
    {ok, Bin} = file:read_file(Path),
    Bin.

delete(Path) ->
    ok = file:delete(Path),
    nil.

copy(From, To) ->
    {ok, _} = file:copy(From, To),
    nil.

%% {Permitted names, CA flag, path length, validity seconds, key usage}
root_shape(Pem) ->
    [{'Certificate', Der, not_encrypted}] = public_key:pem_decode(Pem),
    #'OTPCertificate'{tbsCertificate = Tbs} = public_key:pkix_decode_cert(Der, otp),
    Exts = Tbs#'OTPTBSCertificate'.extensions,
    #'Extension'{critical = true,
                 extnValue = #'NameConstraints'{permittedSubtrees = Permitted,
                                                excludedSubtrees = asn1_NOVALUE}} =
        lists:keyfind(?'id-ce-nameConstraints', #'Extension'.extnID, Exts),
    #'Extension'{critical = true,
                 extnValue = #'BasicConstraints'{cA = CA, pathLenConstraint = PathLen}} =
        lists:keyfind(?'id-ce-basicConstraints', #'Extension'.extnID, Exts),
    #'Extension'{extnValue = Usage} =
        lists:keyfind(?'id-ce-keyUsage', #'Extension'.extnID, Exts),
    Names = [name(Base) || #'GeneralSubtree'{base = Base} <- Permitted],
    #'Validity'{notBefore = From, notAfter = To} = Tbs#'OTPTBSCertificate'.validity,
    {Names, CA, PathLen, seconds(To) - seconds(From),
     lists:sort([atom_to_binary(U) || U <- Usage])}.

name({dNSName, Name}) -> <<"dns:", (list_to_binary(Name))/binary>>;
name({iPAddress, <<A, B, C, D, 255, 255, 255, 255>>}) ->
    iolist_to_binary(io_lib:format("ip:~b.~b.~b.~b/32", [A, B, C, D]));
name({iPAddress, <<0:120, 1:8, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:128>>}) -> <<"ip:::1/128">>;
name(Other) -> iolist_to_binary(io_lib:format("~p", [Other])).

%% Sign a leaf for `Name` with the anchor's own key and verify it against the
%% anchor with OpenSSL from the dev shell, which applies a trust anchor's name
%% constraints. (OTP's path validation does not apply a trust anchor's own
%% extensions, as RFC 5280 permits, so it cannot witness them.)
foreign_leaf_validation(Dir) ->
    {openssl(Dir, "example.com"), openssl(Dir, "localhost")}.

openssl(Dir, Name) ->
    Leaf = leaf(Dir, Name),
    LeafPath = filename:join(Dir, <<"probe-leaf.pem">>),
    ok = file:write_file(LeafPath, public_key:pem_encode([{'Certificate', Leaf, not_encrypted}])),
    Out = os:cmd("openssl verify -CAfile " ++ binary_to_list(cert_path(Dir)) ++ " "
                 ++ binary_to_list(LeafPath) ++ " 2>&1"),
    ok = file:delete(LeafPath),
    case string:find(Out, "permitted subtree violation") of
        nomatch ->
            case string:find(Out, ": OK") of
                nomatch -> list_to_binary(Out);
                _ -> <<"ok">>
            end;
        _ -> <<"permitted subtree violation">>
    end.

leaf(Dir, Name) ->
    {RootDer, RootKey} = load(Dir),
    #'OTPCertificate'{tbsCertificate = RootTbs} = public_key:pkix_decode_cert(RootDer, otp),
    LeafKey = public_key:generate_key({namedCurve, ?secp256r1}),
    #'ECPrivateKey'{publicKey = Point} = LeafKey,
    Tbs = #'OTPTBSCertificate'{
             version = v3,
             serialNumber = 4242,
             signature = #'SignatureAlgorithm'{algorithm = ?'ecdsa-with-SHA256',
                                               parameters = asn1_NOVALUE},
             issuer = RootTbs#'OTPTBSCertificate'.subject,
             validity = RootTbs#'OTPTBSCertificate'.validity,
             subject = {rdnSequence, [[#'AttributeTypeAndValue'{
                                          type = ?'id-at-commonName',
                                          value = {utf8String, list_to_binary(Name)}}]]},
             subjectPublicKeyInfo =
                 #'OTPSubjectPublicKeyInfo'{
                    algorithm = #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey',
                                                      parameters = {namedCurve, ?secp256r1}},
                    subjectPublicKey = #'ECPoint'{point = Point}},
             extensions = [#'Extension'{extnID = ?'id-ce-subjectAltName', critical = false,
                                        extnValue = [{dNSName, Name}]}]},
    _ = RootDer,
    public_key:pkix_sign(Tbs, RootKey).

%% Re-sign the anchor's root with a validity that ended yesterday.
expire(Dir) ->
    {RootDer, RootKey} = load(Dir),
    #'OTPCertificate'{tbsCertificate = Tbs} = public_key:pkix_decode_cert(RootDer, otp),
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    Validity = #'Validity'{notBefore = utc(Now - 10 * 86400), notAfter = utc(Now - 86400)},
    Der = public_key:pkix_sign(Tbs#'OTPTBSCertificate'{validity = Validity}, RootKey),
    ok = file:write_file(cert_path(Dir),
                         public_key:pem_encode([{'Certificate', Der, not_encrypted}])),
    nil.

load(Dir) ->
    {ok, CertPem} = file:read_file(cert_path(Dir)),
    {ok, KeyPem} = file:read_file(filename:join(Dir, <<"hellhound-root-key.pem">>)),
    [{'Certificate', Der, not_encrypted}] = public_key:pem_decode(CertPem),
    [KeyEntry] = public_key:pem_decode(KeyPem),
    {Der, public_key:pem_entry_decode(KeyEntry)}.

cert_path(Dir) -> filename:join(Dir, <<"hellhound-root.pem">>).

utc(Seconds) ->
    {{Y, Mo, D}, {H, Mi, S}} = calendar:gregorian_seconds_to_datetime(Seconds),
    {utcTime, lists:flatten(io_lib:format("~2..0b~2..0b~2..0b~2..0b~2..0b~2..0bZ",
                                          [Y rem 100, Mo, D, H, Mi, S]))}.

seconds({utcTime, [Y1, Y2 | Rest]}) ->
    Year = list_to_integer([Y1, Y2]),
    seconds({generalTime, integer_to_list(if Year >= 50 -> 1900 + Year; true -> 2000 + Year end) ++ Rest});
seconds({generalTime, [Y1, Y2, Y3, Y4, M1, M2, D1, D2, H1, H2, I1, I2, S1, S2, $Z]}) ->
    calendar:datetime_to_gregorian_seconds(
      {{list_to_integer([Y1, Y2, Y3, Y4]), list_to_integer([M1, M2]), list_to_integer([D1, D2])},
       {list_to_integer([H1, H2]), list_to_integer([I1, I2]), list_to_integer([S1, S2])}}).

%% Start `Count` separate OS processes (`erl`) at once, each loading or
%% creating the anchor in `Dir` through the library's own Gleam module
%% (`hellhound/internal/test_anchor`), and return the PEM of the root each
%% one got.
os_process_roots(Dir, Count) ->
    Paths = [P || P <- code:get_path(), string:find(P, "/build/") =/= nomatch],
    Erl = os:find_executable("erl"),
    Eval = lists:flatten(io_lib:format(
             "{ok, Root} = 'hellhound@internal@test_anchor':load_or_create(~p), "
             "io:put_chars(binary:encode_hex('hellhound@internal@test_anchor':root_der(Root))), "
             "halt().", [Dir])),
    Ports = [open_port({spawn_executable, Erl},
                       [{args, ["-noshell", "-pa" | Paths] ++ ["-eval", Eval]},
                        binary, exit_status, use_stdio])
             || _ <- lists:seq(1, Count)],
    [collect(Port, <<>>) || Port <- Ports].

collect(Port, Acc) ->
    receive
        {Port, {data, Data}} -> collect(Port, <<Acc/binary, Data/binary>>);
        {Port, {exit_status, 0}} ->
            public_key:pem_encode([{'Certificate', binary:decode_hex(Acc), not_encrypted}]);
        {Port, {exit_status, Status}} ->
            iolist_to_binary(io_lib:format("exit ~b: ~s", [Status, Acc]))
    after 60000 -> <<"timeout">>
    end.

%% Keep the key file's public point but replace its private scalar with
%% another key's, as a damaged or tampered key file would.
swap_scalar(Dir) ->
    Path = filename:join(Dir, <<"hellhound-root-key.pem">>),
    {ok, Pem} = file:read_file(Path),
    [Entry] = public_key:pem_decode(Pem),
    Key = public_key:pem_entry_decode(Entry),
    #'ECPrivateKey'{privateKey = Other} = public_key:generate_key({namedCurve, ?secp256r1}),
    Swapped = Key#'ECPrivateKey'{privateKey = Other},
    %% PKCS#8, as the anchor stores it; it wraps the same ECPrivateKey,
    %% stored public point included.
    ok = file:write_file(Path, public_key:pem_encode(
                                 [public_key:pem_entry_encode('PrivateKeyInfo', Swapped)])),
    nil.

%% Re-sign the anchor's root with its own key after one change to its
%% profile, as a hand-edited or foreign root would be.
resign(Dir, Change) ->
    {_, RootKey} = load(Dir),
    {RootDer, _} = load(Dir),
    #'OTPCertificate'{tbsCertificate = Tbs} = public_key:pkix_decode_cert(RootDer, otp),
    Exts = Tbs#'OTPTBSCertificate'.extensions,
    Changed = change(Change, Tbs, Exts),
    Der = public_key:pkix_sign(Changed, RootKey),
    ok = file:write_file(cert_path(Dir),
                         public_key:pem_encode([{'Certificate', Der, not_encrypted}])),
    nil.

change(<<"no_extensions">>, Tbs, _) ->
    Tbs#'OTPTBSCertificate'{extensions = asn1_NOVALUE};
change(<<"digital_signature_usage">>, Tbs, Exts) ->
    Tbs#'OTPTBSCertificate'{extensions = replace(Exts, ?'id-ce-keyUsage',
        fun(E) -> E#'Extension'{extnValue = [digitalSignature]} end)};
change(<<"non_critical_key_usage">>, Tbs, Exts) ->
    Tbs#'OTPTBSCertificate'{extensions = replace(Exts, ?'id-ce-keyUsage',
        fun(E) -> E#'Extension'{critical = false} end)};
change(<<"no_key_usage">>, Tbs, Exts) ->
    Tbs#'OTPTBSCertificate'{extensions =
        lists:keydelete(?'id-ce-keyUsage', #'Extension'.extnID, Exts)};
change(<<"non_critical_name_constraints">>, Tbs, Exts) ->
    Tbs#'OTPTBSCertificate'{extensions = replace(Exts, ?'id-ce-nameConstraints',
        fun(E) -> E#'Extension'{critical = false} end)};
change(<<"wider_name_constraints">>, Tbs, Exts) ->
    Tbs#'OTPTBSCertificate'{extensions = replace(Exts, ?'id-ce-nameConstraints',
        fun(#'Extension'{extnValue = NC = #'NameConstraints'{permittedSubtrees = P}} = E) ->
            Wider = #'GeneralSubtree'{base = {dNSName, "example.com"}, minimum = 0,
                                      maximum = asn1_NOVALUE},
            E#'Extension'{extnValue = NC#'NameConstraints'{permittedSubtrees = P ++ [Wider]}}
        end)};
change(<<"no_path_length">>, Tbs, Exts) ->
    Tbs#'OTPTBSCertificate'{extensions = replace(Exts, ?'id-ce-basicConstraints',
        fun(E) -> E#'Extension'{extnValue = #'BasicConstraints'{cA = true,
                                    pathLenConstraint = asn1_NOVALUE}} end)};
change(<<"extra_extension">>, Tbs, Exts) ->
    Tbs#'OTPTBSCertificate'{extensions = Exts ++
        [#'Extension'{extnID = ?'id-ce-extKeyUsage', critical = false,
                      extnValue = [?'id-kp-serverAuth']}]};
change(<<"duplicate_extension">>, Tbs, Exts) ->
    Tbs#'OTPTBSCertificate'{extensions = Exts ++
        [lists:keyfind(?'id-ce-keyUsage', #'Extension'.extnID, Exts)]};
change(<<"long_validity">>, Tbs, _Exts) ->
    #'Validity'{notBefore = From} = Tbs#'OTPTBSCertificate'.validity,
    Tbs#'OTPTBSCertificate'{validity = #'Validity'{notBefore = From,
        notAfter = utc(seconds(From) + 3650 * 86400)}};
change(<<"sha384">>, Tbs, _Exts) ->
    Tbs#'OTPTBSCertificate'{signature = #'SignatureAlgorithm'{
        algorithm = ?'ecdsa-with-SHA384', parameters = asn1_NOVALUE}};
change(<<"version_one">>, Tbs, _Exts) ->
    Tbs#'OTPTBSCertificate'{version = v1, extensions = asn1_NOVALUE}.

replace(Exts, Id, Fun) ->
    lists:keyreplace(Id, #'Extension'.extnID, Exts,
                     Fun(lists:keyfind(Id, #'Extension'.extnID, Exts))).
