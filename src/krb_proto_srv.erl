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

-module(krb_proto_srv).
-behaviour(gen_server).

-include("KRB5.hrl").

-compile([{parse_transform, lager_transform}]).

-export([
    start_link/1,
    start_req/6,
    cancel_req/2
    ]).

-export([
    init/1,
    terminate/3,
    handle_call/3,
    handle_cast/2,
    handle_info/2
    ]).

-spec start_link(krb_client:config()) -> {ok, krb_proto_srv()}.
start_link(Config = #{realm := _Realm}) ->
    gen_server:start_link(?MODULE, [Config], []).

-type krb_proto_srv() :: pid().

-spec start_req(krb_proto_srv(), tcp | udp, integer(), atom(), term(), [atom()]) -> {ok, reference()}.
start_req(Pid, Proto, N, Type, Msg, Expect) ->
    gen_server:call(Pid, {req, self(), Proto, N, Type, Msg, Expect}).

scrub_msgq(Ref) ->
    receive
        {krb_reply, Ref, _} -> scrub_msgq(Ref);
        {krb_reply_done, Ref} -> scrub_msgq(Ref);
        {krb_error, Ref} -> scrub_msgq(Ref)
    after 0 ->
        ok
    end.

-spec cancel_req(krb_proto_srv(), reference()) -> ok.
cancel_req(Pid, Ref) ->
    gen_server:call(Pid, {cancel, Ref}),
    scrub_msgq(Ref),
    ok.

-type req_ref() :: reference().
-type proto_fsm_ref() :: reference().

-record(req, {
    pid :: pid(),
    protorefs = [] :: [proto_fsm_ref()]
    }).

-record(?MODULE, {
    config :: krb_client:config(),
    refmap = #{} :: #{proto_fsm_ref() => req_ref()},
    reqs = #{} :: #{req_ref() => #req{}},
    udps = [] :: [pid()],
    tcps = [] :: [pid()]
    }).

init([Config]) ->
    #{realm := Realm, kdc := Kdcs} = Config,
    Timeout = maps:get(timeout, Config, 1000),
    Retries = maps:get(retries, Config, 3),
    MaxTimeout = 10000,
    Delay = 1000,
    MaxDelay = 5000,
    Parallel = maps:get(parallel, Config, 3),
    RConfig = #{
        timeout => Timeout, max_timeout => MaxTimeout,
        delay => Delay, max_delay => MaxDelay,
        retries => Retries
    },
    KdcsRandomised = [Kdc || {_, Kdc} <-
        lists:sort([{rand:uniform(), Kdc} || Kdc <- Kdcs])],
    KdcsTruncated = lists:sublist(KdcsRandomised, Parallel),
    UDPs = lists:map(fun ({Host, Port}) ->
        {ok, UDP} = krb_proto_udp_fsm:start_link(self(), Realm,
            Host, Port, RConfig),
        UDP
    end, KdcsRandomised),
    TCPs = lists:map(fun ({Host, Port}) ->
        {ok, TCP} = krb_proto_tcp_fsm:start_link(self(), Realm,
            Host, Port, RConfig),
        TCP
    end, KdcsTruncated),
    {ok, #?MODULE{config = Config, udps = UDPs, tcps = TCPs}}.

terminate(Why, State, #?MODULE{}) ->
    lager:debug("terminating from ~p due to ~p", [State, Why]),
    ok.

-spec get_n_prefs(integer(), term(), [pid()]) -> {[proto_fsm_ref()], [pid()], [pid()]}.
get_n_prefs(0, _Call, Rem) -> {[], [], Rem};
get_n_prefs(_N, _Call, []) -> {[], [], []};
get_n_prefs(N, Call, [Next | Rem]) ->
    case gen_statem:call(Next, Call) of
        {ok, PRef} ->
            {PRefs0, Used, NotUsed} = get_n_prefs(N - 1, Call, Rem),
            {[PRef | PRefs0], [Next | Used], NotUsed};
        _ ->
            {PRefs0, Used, NotUsed} = get_n_prefs(N, Call, Rem),
            {PRefs0, [Next | Used], NotUsed}
    end.

get_n_prefs_proto(tcp, S0 = #?MODULE{tcps = Pids0}, N, Call) ->
    {PRefs, Used, NotUsed} = get_n_prefs(N, Call, Pids0),
    Pids1 = NotUsed ++ lists:reverse(Used),
    {PRefs, S0#?MODULE{tcps = Pids1}};
get_n_prefs_proto(udp, S0 = #?MODULE{udps = Pids0}, N, Call) ->
    {PRefs, Used, NotUsed} = get_n_prefs(N, Call, Pids0),
    Pids1 = NotUsed ++ lists:reverse(Used),
    {PRefs, S0#?MODULE{udps = Pids1}}.

handle_call({req, Pid, Proto, N, Type, Msg, Expect}, From,
                                            S0 = #?MODULE{reqs = Reqs0,
                                                          refmap = RefMap0}) ->
    Ref = make_ref(),
    gen_server:reply(From, {ok, Ref}),
    {PRefs, S1} = get_n_prefs_proto(Proto, S0, N, {send, Type, Msg, Expect}),
    case PRefs of
        [] ->
            Pid ! {krb_error, Ref},
            {noreply, S1};
        _ ->
            Req0 = #req{pid = Pid, protorefs = PRefs},
            RefMap1 = lists:foldl(fun (PRef, Acc) ->
                Acc#{PRef => Ref}
            end, RefMap0, PRefs),
            Reqs1 = Reqs0#{Ref => Req0},
            S2 = S1#?MODULE{reqs = Reqs1, refmap = RefMap1},
            {noreply, S2}
    end;

handle_call({cancel, Ref}, _From, S0 = #?MODULE{reqs = Reqs0,
                                                refmap = RefMap0}) ->
    #{Ref := Req} = Reqs0,
    #req{protorefs = PRefs} = Req,
    Reqs1 = maps:remove(Ref, Reqs0),
    RefMap1 = lists:foldl(fun (PRef, Acc) ->
        maps:remove(PRef, Acc)
    end, RefMap0, PRefs),
    S1 = S0#?MODULE{reqs = Reqs1, refmap = RefMap1},
    {reply, ok, S1}.

handle_info({krb_reply, PRef, Msg}, S0 = #?MODULE{refmap = RefMap0,
                                                  reqs = Reqs0}) ->
    case RefMap0 of
        #{PRef := Ref} ->
            #{Ref := Req0} = Reqs0,
            #req{pid = Pid, protorefs = PRefs0} = Req0,
            Pid ! {krb_reply, Ref, Msg},
            case PRefs0 of
                [PRef] -> Pid ! {krb_reply_done, Ref};
                _ -> ok
            end,
            RefMap1 = maps:remove(PRef, RefMap0),
            PRefs1 = PRefs0 -- [PRef],
            Req1 = Req0#req{protorefs = PRefs1},
            Reqs1 = Reqs0#{Ref => Req1},
            S1 = S0#?MODULE{reqs = Reqs1, refmap = RefMap1},
            {noreply, S1};
        _ ->
            {noreply, S0}
    end;
handle_info({krb_error, PRef}, S0 = #?MODULE{refmap = RefMap0,
                                             reqs = Reqs0}) ->
    case RefMap0 of
        #{PRef := Ref} ->
            #{Ref := Req0} = Reqs0,
            #req{pid = Pid, protorefs = PRefs0} = Req0,
            case PRefs0 of
                [PRef] -> Pid ! {krb_error, Ref};
                _ -> ok
            end,
            RefMap1 = maps:remove(PRef, RefMap0),
            PRefs1 = PRefs0 -- [PRef],
            Req1 = Req0#req{protorefs = PRefs1},
            Reqs1 = Reqs0#{Ref => Req1},
            S1 = S0#?MODULE{reqs = Reqs1, refmap = RefMap1},
            {noreply, S1};
        _ ->
            {noreply, S0}
    end.

handle_cast(C, S0) ->
    {stop, {unsupported_cast, C}, S0}.
