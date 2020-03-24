%% kerlberos
%%
%% Copyright 2015 Alex Wilson <alex@uq.edu.au>
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

-module(krbcc).

-include("KRB5.hrl").
-behaviour(gen_server).

-export([start_link/2, stop/1]).
-export([store_ticket/4, get_ticket/4, find_tickets/2]).
-export([init/1, terminate/2, handle_call/3]).

-callback init(Opts :: map()) -> {ok, State :: term()}.
-callback store_ticket(UserPrincipal :: string(), Key :: term(), Ticket :: #'Ticket'{}, State :: term()) -> {ok, State2 :: term()} | {error, Reason :: term()}.
-callback get_ticket(UserPrincipal :: string(), ServicePrincipal :: string(), Realm :: string(), State :: term()) -> {ok, Key :: term(), Ticket :: #'Ticket'{}} | {error, not_found} | {error, Reason :: term()}.
-callback find_tickets(Filter :: map(), State :: term()) -> {ok, [map()]} | {error, not_found} | {error, Reason :: term()}.
-callback terminate(State :: term()) -> ignored.

start_link(Mod, Opts) ->
	gen_server:start_link(?MODULE, [Mod, Opts], []).

stop(CC) ->
	gen_server:call(CC, stop).

store_ticket(CC, UserPrincipal, Key, Ticket) ->
	gen_server:call(CC, {store_ticket, UserPrincipal, Key, Ticket}).

get_ticket(CC, UserPrincipal, ServicePrincipal, Realm) ->
	gen_server:call(CC, {get_ticket, UserPrincipal, ServicePrincipal, Realm}).

find_tickets(CC, Filter) ->
	case Filter of
		#{user_principal := _} -> ok;
		#{service_principal := _} -> ok
	end,
	gen_server:call(CC, {find_tickets, Filter}).

-record(krbcc_state, {mod, modstate, opts}).

init([Mod, Opts]) ->
	{ok, ModState0} = Mod:init(Opts),
	{ok, #krbcc_state{mod = Mod, modstate = ModState0, opts = Opts}}.

terminate(_Reason, #krbcc_state{mod = Mod, modstate = ModState0}) ->
	Mod:terminate(ModState0),
	ok.

handle_call({store_ticket, UserPrincipal, Key, Ticket}, _From,
	    S0 = #krbcc_state{mod = Mod, modstate = ModState0}) ->
	case Mod:store_ticket(UserPrincipal, Key, Ticket, ModState0) of
		{ok, ModState1} -> {reply, ok, S0#krbcc_state{modstate = ModState1}};
		{error, Reason} -> {reply, {error, Reason}, S0}
	end;

handle_call({get_ticket, UserPrincipal, ServicePrincipal, Realm}, _From,
	    S0 = #krbcc_state{mod = Mod, modstate = ModState0}) ->
	Res = Mod:get_ticket(UserPrincipal, ServicePrincipal, Realm, ModState0),
	{reply, Res, S0};

handle_call({find_tickets, Filter}, _From,
	    S0 = #krbcc_state{mod = Mod, modstate = ModState0}) ->
	Res = Mod:find_tickets(Filter, ModState0),
	{reply, Res, S0};

handle_call(stop, _From, S0 = #krbcc_state{}) ->
	{stop, normal, S0}.
