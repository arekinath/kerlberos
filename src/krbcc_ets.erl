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

%% @doc credential cache in ets
-module(krbcc_ets).

-include("KRB5.hrl").

-behaviour(krbcc).
-export([init/1, terminate/1, store_ticket/4, get_ticket/4, find_tickets/2]).

-record(state, {tickets = #{} :: map()}).

init(_Opts) ->
	{ok, #state{}}.

store_ticket(UserPrincipal, Key, Ticket, S0 = #state{tickets = T0}) ->
	#'Ticket'{realm = Realm, sname = SN} = Ticket,
	#'PrincipalName'{'name-string' = ServicePrincipal} = SN,
	T1 = T0#{ {UserPrincipal, ServicePrincipal, Realm} => {Key, Ticket} },
	{ok, S0#state{tickets = T1}}.

get_ticket(UserPrincipal, ServicePrincipal, Realm, S = #state{tickets = T}) ->
	K = {UserPrincipal, ServicePrincipal, Realm},
	case T of
		#{ K := {Key, Ticket} } ->
			{ok, Key, Ticket};
		_ -> {error, not_found}
	end.

find_tickets(#{user_principal := UPN}, S = #state{tickets = T}) ->
	Found = maps:fold(fun (K, V, Acc) ->
		case K of
			{UPN, SPN, Realm} ->
				{Key, Ticket} = V,
				[#{service_principal => SPN, realm => Realm,
				   key => Key, ticket => Ticket} | Acc];
			_ -> Acc
		end
	end, [], T),
	case Found of
		[] -> {error, not_found};
		_ -> {ok, Found}
	end;
find_tickets(#{service_principal := SPN}, S = #state{tickets = T}) ->
	Found = maps:fold(fun (K, V, Acc) ->
		case K of
			{UPN, SPN, Realm} ->
				{Key, Ticket} = V,
				[#{user_principal => UPN, realm => Realm,
				   key => Key, ticket => Ticket} | Acc];
			_ -> Acc
		end
	end, [], T),
	case Found of
		[] -> {error, not_found};
		_ -> {ok, Found}
	end.

terminate(#state{}) -> ok.
