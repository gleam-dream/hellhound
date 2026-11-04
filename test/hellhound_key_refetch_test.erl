%% Unknown-key refetches are bounded by time, not by kid novelty: a token's
%% `kid` is attacker-chosen and unauthenticated until its signature verifies.
%% The JWKS endpoint counts its fetches; a test clock drives the cooldown.
-module(hellhound_key_refetch_test).
-include_lib("eunit/include/eunit.hrl").

-define(COOLDOWN_MS, 30000).
-define(AUDIENCE, <<"https://api.test">>).

distinct_unknown_kids_share_one_refetch_per_cooldown_test() ->
    Key = key(),
    with_jwks([public(Key, <<"k1">>)], fun(Rig) ->
        Validator = validator(Rig),
        ?assertMatch({ok, _}, hellhound@resource:verify(Validator, token(Rig, Key, <<"k1">>))),
        Before = fetches(Rig),
        Results = [hellhound@resource:verify(Validator, token(Rig, Key, random_kid()))
                   || _ <- lists:seq(1, 70)],
        ?assertEqual([{error, unknown_signing_key}], lists:usort(Results)),
        ?assert(fetches(Rig) - Before =< 1),
        ?assertMatch({ok, _}, hellhound@resource:verify(Validator, token(Rig, Key, <<"k1">>)))
    end).

concurrent_unknown_kids_coalesce_into_one_fetch_test() ->
    Key = key(),
    with_jwks([public(Key, <<"k1">>)], fun(Rig) ->
        Validator = validator(Rig),
        Before = fetches(Rig),
        Parent = self(),
        Tokens = [token(Rig, Key, random_kid()) || _ <- lists:seq(1, 20)],
        Refs = [begin
                    Ref = make_ref(),
                    spawn(fun() -> Parent ! {Ref, hellhound@resource:verify(Validator, T)} end),
                    Ref
                end || T <- Tokens],
        Results = [receive {Ref, R} -> R after 10000 -> error(no_result) end || Ref <- Refs],
        ?assertEqual([{error, unknown_signing_key}], lists:usort(Results)),
        ?assert(fetches(Rig) - Before =< 1)
    end).

rotation_within_cooldown_waits_then_refetches_once_test() ->
    Old = key(),
    New = key(),
    with_jwks([public(Old, <<"old">>)], fun(Rig) ->
        Validator = validator(Rig),
        Before = fetches(Rig),
        ?assertEqual({error, unknown_signing_key},
                     hellhound@resource:verify(Validator, token(Rig, Old, random_kid()))),
        ?assertEqual(Before + 1, fetches(Rig)),
        publish(Rig, [public(Old, <<"old">>), public(New, <<"new">>)]),
        %% Within the cooldown a new kid is refused without a fetch.
        ?assertEqual({error, unknown_signing_key},
                     hellhound@resource:verify(Validator, token(Rig, New, <<"new">>))),
        ?assertEqual(Before + 1, fetches(Rig)),
        advance(Rig, ?COOLDOWN_MS - 1),
        ?assertEqual({error, unknown_signing_key},
                     hellhound@resource:verify(Validator, token(Rig, New, <<"new">>))),
        ?assertEqual(Before + 1, fetches(Rig)),
        %% After the cooldown exactly one fetch admits the rotated key.
        advance(Rig, 1),
        ?assertMatch({ok, _}, hellhound@resource:verify(Validator, token(Rig, New, <<"new">>))),
        ?assertEqual(Before + 2, fetches(Rig)),
        ?assertEqual({error, unknown_signing_key},
                     hellhound@resource:verify(Validator, token(Rig, New, random_kid()))),
        ?assertEqual(Before + 2, fetches(Rig))
    end).

unmatched_kid_with_kidless_keys_refetches_test() ->
    Kidless = key(),
    New = key(),
    with_jwks([public(Kidless, none)], fun(Rig) ->
        Validator = validator(Rig),
        Before = fetches(Rig),
        %% Tokens without a kid, or naming a kid the set lacks, are still
        %% checked against kid-less keys.
        ?assertMatch({ok, _}, hellhound@resource:verify(Validator, token(Rig, Kidless, none))),
        ?assertMatch({ok, _}, hellhound@resource:verify(Validator, token(Rig, Kidless, <<"absent">>))),
        ?assertEqual(Before, fetches(Rig)),
        publish(Rig, [public(Kidless, none), public(New, <<"new">>)]),
        %% A kid matching no cached key is an unknown key, not a bad signature.
        ?assertMatch({ok, _}, hellhound@resource:verify(Validator, token(Rig, New, <<"new">>))),
        ?assertEqual(Before + 1, fetches(Rig)),
        %% Without a kid, a wrong key remains a bad signature and never fetches.
        ?assertEqual({error, bad_signature},
                     hellhound@resource:verify(Validator, token(Rig, key(), none))),
        ?assertEqual(Before + 1, fetches(Rig))
    end).

%% ---------------------------------------------------------------------------

with_jwks(Keys, Fun) ->
    {ok, _} = application:ensure_all_started(hellhound),
    {ok, _} = application:ensure_all_started(jose),
    Table = ets:new(hellhound_key_refetch, [public, set]),
    Count = atomics:new(1, []),
    ets:insert(Table, {keys, Keys}),
    Jwks = hellhound_test_server:start("localhost", fun(_) ->
        atomics:add(Count, 1, 1),
        [{keys, Current}] = ets:lookup(Table, keys),
        {respond, 200, [{<<"content-type">>, <<"application/json">>}],
         json:encode(#{<<"keys">> => Current})}
    end),
    Test = hellhound_test_provider:start(#{<<"jwks_uri">> => hellhound_test_server:url(Jwks, <<"/keys">>)}),
    Clock = hellhound_test_support_ffi:clock_new(0),
    try
        Config0 = hellhound@config:resource_server(hellhound_test_provider:issuer(Test)),
        Config1 = hellhound@config:with_trust(Config0, {trust_anchors_pem, hellhound_test_support_ffi:ca_pem()}),
        Config2 = hellhound@config:with_destinations(Config1, allow_loopback_for_testing),
        Config = hellhound_test_support:with_monotonic_clock(Config2, Clock),
        {ok, Client} = hellhound:new(Config),
        try
            {ok, nil} = hellhound:start(Client),
            Fun(#{client => Client, table => Table, count => Count, clock => Clock,
                  issuer => hellhound_test_provider:issuer(Test)})
        after hellhound:stop(Client) end
    after
        hellhound_test_provider:stop(Test),
        hellhound_test_server:stop(Jwks),
        ets:delete(Table)
    end.

validator(#{client := Client}) -> hellhound@resource:new(Client, ?AUDIENCE).
fetches(#{count := Count}) -> atomics:get(Count, 1).
publish(#{table := Table}, Keys) -> ets:insert(Table, {keys, Keys}).
advance(#{clock := Clock}, Ms) ->
    hellhound_test_support_ffi:clock_set(Clock, hellhound_test_support_ffi:clock_read(Clock) + Ms).

key() -> jose_jwk:generate_key({rsa, 2048}).

public(Key, Kid) ->
    {_, Public} = jose_jwk:to_public_map(Key),
    Base = Public#{<<"use">> => <<"sig">>, <<"alg">> => <<"RS256">>},
    case Kid of none -> Base; _ -> Base#{<<"kid">> => Kid} end.

random_kid() -> base64:encode(crypto:strong_rand_bytes(12), #{mode => urlsafe, padding => false}).

token(#{issuer := Issuer}, Key, Kid) ->
    Now = erlang:system_time(second),
    Claims = #{<<"iss">> => Issuer, <<"sub">> => <<"ada">>, <<"aud">> => ?AUDIENCE,
               <<"exp">> => Now + 300, <<"iat">> => Now, <<"jti">> => random_kid(),
               <<"client_id">> => <<"hellhound-rp">>},
    Header0 = #{<<"alg">> => <<"RS256">>, <<"typ">> => <<"at+jwt">>},
    Header = case Kid of none -> Header0; _ -> Header0#{<<"kid">> => Kid} end,
    {_, Token} = jose_jws:compact(jose_jwt:sign(Key, Header, Claims)),
    Token.
