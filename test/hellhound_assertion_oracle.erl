%% Test-only independent JOSE implementation. No runtime dependency.
-module(hellhound_assertion_oracle).
-export([key/1, verify/3, pem/2, malformed_rsa_pem/2, rfc_vector/0, emit/2]).

key(Kind) ->
    Type = case Kind of
        <<"RSA">> -> {rsa, 2048};
        <<"weak">> -> {rsa, 1024};
        <<"EC">> -> {ec, <<"P-256">>};
        <<"Ed25519">> -> {okp, 'Ed25519'}
    end,
    {_, Json} = jose_jwk:to_binary(jose_jwk:generate_key(Type)),
    Json.

verify(Token, Json, Algorithm) ->
    try
        Key = jose_jwk:from_binary(Json),
        case jose_jwt:verify_strict(jose_jwk:to_public(Key), [Algorithm], Token) of
            {true, Jwt, _} ->
                {_, Claims} = jose_jwt:to_binary(Jwt),
                {ok, Claims};
            _ -> {error, nil}
        end
    catch _:_ -> {error, nil}
    end.

pem(Json, Format) ->
    Key = jose_jwk:from_binary(Json),
    case Format of
        <<"pkcs8">> -> element(2, jose_jwk:to_pem(Key));
        <<"public">> -> element(2, jose_jwk:to_pem(jose_jwk:to_public(Key)));
        <<"pkcs1">> ->
            {_, Raw} = jose_jwk:to_key(Key),
            public_key:pem_encode([public_key:pem_entry_encode('RSAPrivateKey', Raw)])
    end.

malformed_rsa_pem(Json, Field) ->
    {_, Raw} = jose_jwk:to_key(jose_jwk:from_binary(Json)),
    Invalid = setelement(Field, Raw, -1),
    public_key:pem_encode([public_key:pem_entry_encode('RSAPrivateKey', Invalid)]).

%% Inputs are fetched at a checked digest by scripts/prepare-assertion-oracles.
rfc_vector() ->
    {ok, Bytes} = file:read_file("build/oracle-inputs/rfc7520-rs256.json"),
    #{<<"input">> := Input, <<"output">> := Output} = json:decode(Bytes),
    {iolist_to_binary(json:encode(maps:get(<<"key">>, Input))),
     maps:get(<<"payload">>, Input), maps:get(<<"compact">>, Output)}.

emit(Token, Json) ->
    ok = filelib:ensure_dir("build/assertion-oracles/output.json"),
    Public = element(2, jose_jwk:to_map(jose_jwk:to_public(jose_jwk:from_binary(Json)))),
    Bytes = json:encode(#{<<"token">> => Token, <<"key">> => Public}),
    ok = file:write_file("build/assertion-oracles/output.json", Bytes),
    nil.
