%% kerlberos
%%
%% Copyright (c) 2015, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(login_kerlberos).
-behaviour(bsdauth).

-export([main/1, can_handle/3, verify/4]).

main(Args) -> bsdauth:main(?MODULE, Args).

config() ->
	case conf_parse:file("/etc/kerlberos.conf") of
		{error, enoent} -> [];
		ConfPlist -> ConfPlist
	end.

open_client(Config) ->
	Realm = case proplists:get_value(["realm"], Config) of
		undefined ->
			{ok, Host} = inet:gethostname(),
			{ok, {hostent,Fqdn,[],inet,_,[_]}} = inet:gethostbyname(Host),
			case string:tokens(Fqdn, ".") of
				[_ | Domain] -> string:to_upper(string:join(Domain, "."));
				_ -> string:to_upper(Fqdn)
			end;
		Val -> string:to_upper(Val)
	end,
	Opts0 = case proplists:get_value(["ciphers"], Config) of
		undefined -> [];
		CipherList -> [{ciphers, [list_to_atom(X) || X <- string:tokens(CipherList, ", ")]}]
	end,
	Opts1 = case proplists:get_value(["timeout"], Config) of
		undefined -> Opts0;
		TVal -> [{timeout, list_to_integer(TVal)} | Opts0]
	end,
	Opts2 = case proplists:get_all_values(["kdc"], Config) of
		[] -> Opts1;
		undefined -> Opts1;
		KdcList when is_list(KdcList) ->
			Kdcs = lists:map(fun(E) ->
				case string:tokens(E, ":") of
					[HostPart, PortPart] -> {HostPart, list_to_integer(PortPart)};
					_ -> E
				end
			end, KdcList),
			[{kdc, Kdcs} | Opts1]
	end,
	krb_client:open(Realm, Opts2).

check_user_exists(Username, Config) ->
	case proplists:get_value(["users","fallback"], Config, "true") of
		V when V =:= "true"; V =:= "yes" ->
			{ok, C} = open_client(Config),
			case krb_client:authenticate(C, Username, "-") of
				{error, bad_principal} -> false;
				{error, _} -> true
			end;
		_ -> false
	end.

can_handle(Username, _Class, _Dict) ->
	Config = config(),
	case proplists:get_all_values(["users","blacklist"], Config) of
		L when is_list(L) ->
			Blacklist = lists:flatmap(fun(X) -> string:tokens(X, ", ") end, L),
			case lists:member(Username, Blacklist) of
				true -> false;
				_ -> check_user_exists(Username, Config)
			end;
		_ -> check_user_exists(Username, Config)
	end.

verify(Username, Password, _Class, _Dict) ->
	Config = config(),
	{ok, C} = open_client(Config),
	case krb_client:authenticate(C, Username, binary_to_list(Password)) of
		ok ->
			Realm = string:to_upper(proplists:get_value(["realm"], Config, "default")),
			{true, [{setenv, "KRB5_REALM", Realm}]};
		{error, Atom} when Atom =:= bad_secret; Atom =:= bad_principal ->
			{false, [{error, "Login incorrect"}]};
		{error, Err} ->
			{false, [{error, io_lib:format("Kerberos error: ~999p", [Err])}]}
	end.
