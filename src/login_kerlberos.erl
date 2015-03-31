%% kerlberos
%%
%% Copyright (c) 2015, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(login_kerlberos).
-behaviour(bsdauth).

-export([main/1, verify/4]).

main(Args) -> bsdauth:main(?MODULE, Args).

verify(Username, Password, _Class, _Dict) ->
	Config = case conf_parse:file("/etc/kerlberos.conf") of
		{error, enoent} -> [];
		ConfPlist -> ConfPlist
	end,
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
	{ok, C} = krb_client:open(Realm, Opts2),
	case krb_client:authenticate(C, Username, binary_to_list(Password)) of
		ok ->
			{true, [{setenv, "KRB5_REALM", Realm}]};
		{error, Atom} when Atom =:= bad_secret; Atom =:= bad_principal ->
			{false, [{error, "Login incorrect"}]};
		{error, Err} ->
			{false, [{error, io_lib:format("Kerberos error: ~999p", [Err])}]}
	end.
