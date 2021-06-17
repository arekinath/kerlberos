%% kerlberos
%%
%% Copyright 2021 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(gss_spnego).
-behaviour(gss_mechanism).

-compile([{parse_transform, lager_transform}]).

-include("KRB5.hrl").
-include("SPNEGO.hrl").

% see rfc4178

-export([
    initiate/1,
    accept/2,
    continue/2
    %delete/1
    ]).

-export([
    wrap/2,
    unwrap/2,
    get_mic/2,
    verify_mic/3
    ]).

-export([
    local_name/1,
    peer_name/1,
    translate_name/2
    ]).

-type oid() :: tuple().

-type config() :: #{mech_prefs => [oid()]} | gss_mechanism:config().

-record(?MODULE, {
    party :: acceptor | initiator,
    state :: initial | running,
    want_mic = false :: boolean(),
    config :: config(),
    mech :: oid(),
    mechmod :: module(),
    mechstate :: term()
    }).

-define(mechs, #{
    {1,2,3,4} => gss_krb5,
    ?'id-mech-krb5' => gss_krb5
    }).
-define(default_mech_prefs, [{1,2,3,4}, ?'id-mech-krb5']).

spnego_initiator_fsm(initial, _, S0 = #?MODULE{config = Opts}) ->
    MechPrefs = maps:get(mech_prefs, Opts, ?default_mech_prefs),
    TokenRec = #'NegTokenInit'{
        mechTypes = MechPrefs
        %negHints = #'NegHints'{
        %    hintName = "not_defined_in_RFC4178@please_ignore"
        %}
    },
    {ok, MechData} = 'SPNEGO':encode('NegotiationToken',
        {'negTokenInit', TokenRec}),
    Token = gss_token:encode_initial(?'id-mech-spnego', MechData),
    S1 = S0#?MODULE{state = await_mech},
    {continue, Token, S1};
spnego_initiator_fsm(await_mech, T = #'NegTokenResp'{}, S0 = #?MODULE{}) ->
    #'NegTokenResp'{negState = NS, supportedMech = Mech} = T,
    #?MODULE{config = Opts} = S0,
    case ?mechs of
        #{Mech := Mod} ->
            S1 = S0#?MODULE{mech = Mech, mechmod = Mod},
            case Mod:initiate(Opts) of
                {ok, MToken0, MS0} when (NS =:= 'request-mic') ->
                    S2 = S1#?MODULE{mechstate = MS0},
                    {MIC, S3} = make_mechlist_mic(S2),
                    TokenRec = #'NegTokenResp'{
                        negState = 'request-mic',
                        responseToken = MToken0,
                        mechListMIC = MIC
                    },
                    {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                        {'negTokenResp', TokenRec}),
                    S4 = S3#?MODULE{state = accepted, want_mic = true},
                    {continue, Token, S4};
                {ok, MToken0, MS0} ->
                    TokenRec = #'NegTokenResp'{
                        negState = 'accept-completed',
                        responseToken = MToken0
                    },
                    {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                        {'negTokenResp', TokenRec}),
                    S2 = S1#?MODULE{state = accepted, mechstate = MS0,
                                    want_mic = false},
                    {continue, Token, S2};
                {continue, MToken0, MS0} ->
                    TokenRec = #'NegTokenResp'{
                        negState = 'accept-incomplete',
                        responseToken = MToken0
                    },
                    {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                        {'negTokenResp', TokenRec}),
                    S2 = S1#?MODULE{state = continue, mechstate = MS0,
                                    want_mic = (NS =:= 'request-mic')},
                    {continue, Token, S2};
                Err = {error, _Why} -> Err
            end;
        _ ->
            lager:debug("remote side tried unknown spnego mech ~p, rejecting",
                [Mech]),
            TokenRec = #'NegTokenResp'{
                negState = 'reject'
            },
            {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                {'negTokenResp', TokenRec}),
            S1 = S0#?MODULE{state = err_next, mech = Mech},
            {continue, Token, S1}
    end;
spnego_initiator_fsm(accepted,
        T = #'NegTokenResp'{negState = 'accept-completed'},
        S0 = #?MODULE{want_mic = false}) ->
    S1 = S0#?MODULE{state = running},
    {ok, S1};
spnego_initiator_fsm(accepted,
        T = #'NegTokenResp'{negState = 'accept-completed', mechListMIC = MIC},
        S0 = #?MODULE{want_mic = true}) ->
    case verify_mechlist_mic(MIC, S0) of
        {true, S1} ->
            S2 = S1#?MODULE{state = running},
            {ok, S2};
        {false, _S1} ->
            {error, defective_token}
    end;
spnego_initiator_fsm(continue, T = #'NegTokenResp'{}, S0 = #?MODULE{}) ->
    #'NegTokenResp'{negState = NS, responseToken = MToken0,
                    mechListMIC = MIC} = T,
    #?MODULE{config = Opts, mechmod = Mod, mechstate = MS0,
             want_mic = WantMIC0} = S0,
    WantMIC1 = case NS of
        'request-mic' -> true;
        _ -> WantMIC0
    end,
    WantMIC2 = case MIC of
        asn1_NOVALUE -> WantMIC1;
        _ -> true
    end,
    case WantMIC2 of
        true ->
            case Mod:continue(MToken0, MS0) of
                {ok, MS1} ->
                    S1 = S0#?MODULE{mechstate = MS1},
                    case verify_mechlist_mic(MIC, S1) of
                        {true, S2} ->
                            {OurMIC, S3} = make_mechlist_mic(S2),
                            TokenRec = #'NegTokenResp'{
                                negState = 'accept-completed',
                                mechListMIC = OurMIC
                            },
                            {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                                {'negTokenResp', TokenRec}),
                            S4 = S3#?MODULE{state = running,
                                            want_mic = true},
                            {ok, Token, S4};
                        {false, S2} ->
                            {error, defective_token}
                    end;
                {ok, MToken1, MS1} ->
                    S1 = S0#?MODULE{mechstate = MS1},
                    case verify_mechlist_mic(MIC, S1) of
                        {true, S2} ->
                            {OurMIC, S3} = make_mechlist_mic(S2),
                            TokenRec = #'NegTokenResp'{
                                negState = 'accept-completed',
                                responseToken = MToken1,
                                mechListMIC = OurMIC
                            },
                            {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                                {'negTokenResp', TokenRec}),
                            S4 = S3#?MODULE{state = accepted, want_mic = true},
                            {continue, Token, S4};
                        {false, S2} ->
                            {error, defective_token}
                    end;
                {continue, MToken1, MS1} ->
                    S1 = S0#?MODULE{mechstate = MS1},
                    case verify_mechlist_mic(MIC, S1) of
                        {true, S2} ->
                            TokenRec = #'NegTokenResp'{
                                negState = 'accept-incomplete',
                                responseToken = MToken1
                            },
                            {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                                {'negTokenResp', TokenRec}),
                            S3 = S2#?MODULE{state = continue, mechstate = MS1,
                                            want_mic = true},
                            {continue, Token, S3};
                        {false, S2} ->
                            {error, defective_token}
                    end;
                Err = {error, _Why} -> Err
            end;
        false ->
            case Mod:continue(MToken0, MS0) of
                {ok, MS1} ->
                    TokenRec = #'NegTokenResp'{
                        negState = 'accept-completed'
                    },
                    {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                        {'negTokenResp', TokenRec}),
                    S1 = S0#?MODULE{state = running, mechstate = MS1},
                    {ok, Token, S1};

                {ok, MToken1, MS1} ->
                    TokenRec = #'NegTokenResp'{
                        negState = 'accept-completed',
                        responseToken = MToken1
                    },
                    {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                        {'negTokenResp', TokenRec}),
                    S1 = S0#?MODULE{state = accepted, mechstate = MS1},
                    {continue, Token, S1};

                {continue, MToken1, MS1} ->
                    TokenRec = #'NegTokenResp'{
                        negState = 'accept-incomplete',
                        responseToken = MToken1
                    },
                    {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                        {'negTokenResp', TokenRec}),
                    S1 = S0#?MODULE{state = continue, mechstate = MS1},
                    {continue, Token, S1};

                Err = {error, _Why} -> Err
            end
    end;
spnego_initiator_fsm(running, _, S0 = #?MODULE{}) ->
    {error, bad_state}.

select_mech([]) -> {error, no_match};
select_mech([NextPref | Rest]) ->
    case ?mechs of
        #{NextPref := Mod} -> {ok, NextPref, Mod};
        _ -> select_mech(Rest)
    end.

spnego_acceptor_fsm(initial, T = #'NegTokenInit'{}, S0 = #?MODULE{}) ->
    #'NegTokenInit'{mechTypes = MechPrefs, mechToken = MToken0} = T,
    #?MODULE{config = Opts, want_mic = WantMIC} = S0,
    case select_mech(MechPrefs) of
        {ok, Mech, Mod} ->
            S1 = S0#?MODULE{state = await_token,
                            mech = Mech, mechmod = Mod},
            IsFirstPref = case MechPrefs of
                [Mech | _] -> true;
                _ -> false
            end,
            HasToken = case MToken0 of
                asn1_NOVALUE -> false;
                _ -> true
            end,
            case {IsFirstPref, HasToken} of
                {true, true} ->
                    Result = Mod:accept(MToken0, Opts),
                    T0 = #'NegTokenResp'{supportedMech = Mech},
                    spnego_accept_common(false, T0, asn1_NOVALUE, Result, S1);
                {_, _} ->
                    TokenRec = #'NegTokenResp'{
                        negState = case WantMIC of
                            true -> 'request-mic';
                            false -> 'accept-incomplete'
                        end,
                        supportedMech = Mech
                    },
                    {ok, MechData} = 'SPNEGO':encode('NegotiationToken',
                        {'negTokenResp', TokenRec}),
                    Token = gss_token:encode_initial(?'id-mech-spnego',
                        MechData),
                    {continue, Token, S1}
            end;
        {error, no_match} ->
            TokenRec = #'NegTokenResp'{
                negState = 'reject'
            },
            {ok, MechData} = 'SPNEGO':encode('NegotiationToken',
                {'negTokenResp', TokenRec}),
            Token = gss_token:encode_initial(?'id-mech-spnego', MechData),
            S1 = S0#?MODULE{state = err_next},
            {continue, Token, S1}
    end;
spnego_acceptor_fsm(await_token, T = #'NegTokenResp'{}, S0 = #?MODULE{}) ->
    #'NegTokenResp'{negState = NS, responseToken = MToken0,
                    mechListMIC = MIC} = T,
    #?MODULE{config = Opts, mechmod = Mod, want_mic = WantMIC0} = S0,
    WantMIC1 = case NS of
        'request-mic' -> true;
        _ -> WantMIC0
    end,
    WantMIC2 = case MIC of
        asn1_NOVALUE -> WantMIC1;
        _ -> true
    end,
    S1 = S0#?MODULE{want_mic = WantMIC2},
    ExpectMIC = case NS of
        'request-mic' -> WantMIC2;
        'accept-completed' -> WantMIC2;
        _ -> false
    end,
    Result = Mod:accept(MToken0, Opts),
    T0 = #'NegTokenResp'{},
    spnego_accept_common(ExpectMIC, T0, MIC, Result, S1);
spnego_acceptor_fsm(continue, T = #'NegTokenResp'{}, S0 = #?MODULE{}) ->
    #'NegTokenResp'{negState = NS, responseToken = MToken0,
                    mechListMIC = MIC} = T,
    #?MODULE{mechmod = Mod, mechstate = MS0, want_mic = WantMIC0} = S0,
    WantMIC1 = case NS of
        'request-mic' -> true;
        _ -> WantMIC0
    end,
    WantMIC2 = case MIC of
        asn1_NOVALUE -> WantMIC1;
        _ -> true
    end,
    S1 = S0#?MODULE{want_mic = WantMIC2},
    ExpectMIC = case NS of
        'request-mic' -> WantMIC2;
        'accept-completed' -> WantMIC2;
        _ -> false
    end,
    Result = Mod:continue(MToken0, MS0),
    T0 = #'NegTokenResp'{},
    spnego_accept_common(WantMIC2, T0, MIC, Result, S1);
spnego_acceptor_fsm(accepted,
                    T = #'NegTokenResp'{negState = 'accept-completed'},
                    S0 = #?MODULE{want_mic = false}) ->
    S1 = S0#?MODULE{state = running},
    {ok, S1};
spnego_acceptor_fsm(accepted,
                    T = #'NegTokenResp'{negState = 'accept-completed',
                                        mechListMIC = MIC},
                    S0 = #?MODULE{want_mic = true}) ->
    case verify_mechlist_mic(MIC, S0) of
        {true, S1} ->
            S2 = S1#?MODULE{state = running},
            {ok, S2};
        {false, _S1} ->
            {error, defective_token}
    end;
spnego_acceptor_fsm(_, _, S0 = #?MODULE{}) ->
    {error, bad_state}.

spnego_accept_common(_ExpectMIC = true, T0, MIC, Result, S0 = #?MODULE{}) ->
    case Result of
        {ok, MS0} ->
            S1 = S0#?MODULE{mechstate = MS0},
            case verify_mechlist_mic(MIC, S1) of
                {true, S2} ->
                    {OurMIC, S3} = make_mechlist_mic(S2),
                    TokenRec = T0#'NegTokenResp'{
                        negState = 'accept-completed',
                        mechListMIC = OurMIC
                    },
                    {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                        {'negTokenResp', TokenRec}),
                    S4 = S3#?MODULE{state = running, want_mic = true},
                    {ok, Token, S4};
                {false, S2} ->
                    {error, defective_token}
            end;
        {ok, MToken1, MS0} ->
            S1 = S0#?MODULE{mechstate = MS0},
            case verify_mechlist_mic(MIC, S1) of
                {true, S2} ->
                    {OurMIC, S3} = make_mechlist_mic(S2),
                    TokenRec = T0#'NegTokenResp'{
                        negState = 'accept-completed',
                        responseToken = MToken1,
                        mechListMIC = OurMIC
                    },
                    {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                        {'negTokenResp', TokenRec}),
                    S4 = S3#?MODULE{state = accepted, want_mic = true},
                    {continue, Token, S4};
                {false, S2} ->
                    {error, defective_token}
            end;
        {continue, MToken1, MS0} ->
            TokenRec = T0#'NegTokenResp'{
                negState = 'request-mic',
                responseToken = MToken1
            },
            {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                {'negTokenResp', TokenRec}),
            S1 = S0#?MODULE{state = continue, mechstate = MS0,
                            want_mic = true},
            {continue, Token, S1};
        Err = {error, _Why} -> Err
    end;
spnego_accept_common(_ExpectMIC = false, T0, MIC, Result, S0 = #?MODULE{}) ->
    #?MODULE{want_mic = WantMIC} = S0,
    case Result of
        {ok, MS0} when WantMIC ->
            S1 = S0#?MODULE{mechstate = MS0},
            {OurMIC, S2} = make_mechlist_mic(S1),
            TokenRec = T0#'NegTokenResp'{
                negState = 'request-mic',
                mechListMIC = OurMIC
            },
            {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                {'negTokenResp', TokenRec}),
            S3 = S2#?MODULE{state = accepted},
            {continue, Token, S3};
        {ok, MS0} ->
            TokenRec = T0#'NegTokenResp'{negState = 'accept-completed'},
            {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                {'negTokenResp', TokenRec}),
            S1 = S0#?MODULE{state = running, mechstate = MS0},
            {ok, Token, S1};
        {ok, MToken1, MS0} when WantMIC ->
            S1 = S0#?MODULE{mechstate = MS0},
            {OurMIC, S2} = make_mechlist_mic(S1),
            TokenRec = T0#'NegTokenResp'{
                negState = 'request-mic',
                responseToken = MToken1,
                mechListMIC = OurMIC
            },
            {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                {'negTokenResp', TokenRec}),
            S3 = S2#?MODULE{state = accepted},
            {continue, Token, S3};
        {ok, MToken1, MS0} ->
            TokenRec = T0#'NegTokenResp'{
                negState = 'accept-completed',
                responseToken = MToken1
            },
            {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                {'negTokenResp', TokenRec}),
            S1 = S0#?MODULE{state = running, mechstate = MS0},
            {ok, Token, S1};
        {continue, MToken1, MS0} ->
            TokenRec = T0#'NegTokenResp'{
                negState = 'accept-incomplete',
                responseToken = MToken1
            },
            {ok, Token} = 'SPNEGO':encode('NegotiationToken',
                {'negTokenResp', TokenRec}),
            S1 = S0#?MODULE{state = continue, mechstate = MS0},
            {continue, Token, S1};
        Err = {error, _Why} -> Err
    end.

make_mechlist_mic(S0 = #?MODULE{config = Opts, mechmod = Mod,
                                mechstate = MS0}) ->
    MechPrefs = maps:get(mech_prefs, Opts, ?default_mech_prefs),
    {ok, MechListBin} = 'SPNEGO':encode('MechTypeList', MechPrefs),
    {ok, MIC, MS1} = Mod:get_mic(MechListBin, MS0),
    S1 = S0#?MODULE{mechstate = MS1},
    {MIC, S1}.

verify_mechlist_mic(asn1_NOVALUE, S0) ->
    {false, S0};
verify_mechlist_mic(MIC, S0 = #?MODULE{config = Opts, mechmod = Mod,
                                       mechstate = MS0}) ->
    MechPrefs = maps:get(mech_prefs, Opts, ?default_mech_prefs),
    {ok, MechListBin} = 'SPNEGO':encode('MechTypeList', MechPrefs),
    case Mod:verify_mic(MechListBin, MIC, MS0) of
        {ok, MS1} ->
            S1 = S0#?MODULE{mechstate = MS1},
            {true, S1};
        {error, Why, MS1} ->
            lager:debug("mechlist MIC failed: ~p", [Why]),
            S1 = S0#?MODULE{mechstate = MS1},
            {false, S1};
        {error, Why} ->
            lager:debug("mechlist MIC failed: ~p", [Why]),
            {false, S0}
    end.

initiate(Opts) ->
    S0 = #?MODULE{config = Opts, party = initiator, state = initial,
                  mech = none, mechmod = none},
    spnego_initiator_fsm(initial, none, S0).

accept(Token, Opts) ->
    S0 = #?MODULE{config = Opts, party = acceptor, state = initial,
                  mech = none, mechmod = none},
    continue(Token, S0).

continue(Token, S0 = #?MODULE{party = initiator, state = State}) ->
    case (catch gss_token:decode_initial(Token)) of
        {'EXIT', _Why} -> MechData = Token;
        {?'id-mech-spnego', MechData, <<>>} -> ok
    end,
    case 'SPNEGO':decode('NegotiationToken', MechData) of
        {ok, {negTokenResp, T}, <<>>} ->
            spnego_initiator_fsm(State, T, S0);
        Err ->
            {error, {defective_token, Err}}
    end;
continue(Token, S0 = #?MODULE{party = acceptor, state = State}) ->
    case (catch gss_token:decode_initial(Token)) of
        {'EXIT', Why} -> MechData = Token;
        {?'id-mech-spnego', MechData, <<>>} -> ok
    end,
    case 'SPNEGO':decode('NegotiationToken', MechData) of
        {ok, {negTokenInit, T}, <<>>} ->
            spnego_acceptor_fsm(State, T, S0);
        {ok, {negTokenResp, T}, <<>>} ->
            spnego_acceptor_fsm(State, T, S0);
        Err ->
            {error, {defective_token, Err}}
    end.

wrap(Message, S0 = #?MODULE{state = running,
                            mechmod = Mod, mechstate = MS0}) ->
    case Mod:wrap(Message, MS0) of
        {ok, Token, MS1} ->
            S1 = S0#?MODULE{mechstate = MS1},
            {ok, Token, S1};
        Err ->
            Err
    end.

unwrap(Token, S0 = #?MODULE{state = running,
                            mechmod = Mod, mechstate = MS0}) ->
    case Mod:unwrap(Token, MS0) of
        {ok, Message, MS1} ->
            S1 = S0#?MODULE{mechstate = MS1},
            {ok, Message, S1};
        {error, Err, MS1} ->
            S1 = S0#?MODULE{mechstate = MS1},
            {error, Err, S1};
        Err ->
            Err
    end.

get_mic(Message, S0 = #?MODULE{state = running,
                               mechmod = Mod, mechstate = MS0}) ->
    case Mod:get_mic(Message, MS0) of
        {ok, Token, MS1} ->
            S1 = S0#?MODULE{mechstate = MS1},
            {ok, Token, S1};
        Err ->
            Err
    end.

verify_mic(Message, Token, S0 = #?MODULE{state = running,
                                         mechmod = Mod, mechstate = MS0}) ->
    case Mod:verify_mic(Message, Token, MS0) of
        {ok, MS1} ->
            S1 = S0#?MODULE{mechstate = MS1},
            {ok, S1};
        {error, Err, MS1} ->
            S1 = S0#?MODULE{mechstate = MS1},
            {error, Err, S1};
        Err ->
            Err
    end.

local_name(S0 = #?MODULE{state = running, mechmod = Mod, mechstate = MS0}) ->
    Mod:local_name(MS0).

peer_name(S0 = #?MODULE{state = running, mechmod = Mod, mechstate = MS0}) ->
    Mod:peer_name(MS0).

translate_name(Name, Oid, [MechMod]) ->
    case MechMod:translate_name(Name, Oid) of
        {ok, DisplayName} -> {ok, DisplayName};
        Err -> Err
    end;
translate_name(Name, Oid, [MechMod | Rest]) ->
    case MechMod:translate_name(Name, Oid) of
        {ok, DisplayName} -> {ok, DisplayName};
        {error, _} -> translate_name(Name, Oid, Rest)
    end.

translate_name(Name, Oid) ->
    MechMods = maps:values(?mechs),
    translate_name(Name, Oid, MechMods).

