%% kerlberos
%%
%% Copyright (c) 2015, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(bsdauth).

-type opt() :: silent | secure | {setenv, Name :: string(), Value :: string()} | {unsetenv, Name :: string()} | {error, string()}.
-type opts() :: [opt()].

-callback verify(Username :: string(), Password :: binary(), Class :: string(), Dict :: dict()) -> true | false | {true | false, opts()}.

-export([main/2]).

-record(args, {dict = dict:new(), service = login :: atom(), username :: string(), class :: undefined | string()}).

process_args(A, ["-v", DictEntry | Rest]) ->
	[K | Vs] = string:tokens(DictEntry, "="),
	V = string:join(Vs, "="),
	process_args(A#args{dict = dict:store(K, V, A#args.dict)}, Rest);
process_args(A, ["-s", Service | Rest]) ->
	process_args(A#args{service = list_to_existing_atom(Service)}, Rest);
process_args(A, [Username, Class]) ->
	A#args{username = Username, class = Class};
process_args(A, [Username]) ->
	A#args{username = Username}.

main(Module, Args) ->
	case (catch process_args(#args{}, Args)) of
		{'EXIT', _} -> usage();
		#args{dict = Dict, service = Service, username = User, class = Class} ->
			case (catch open_port({fd,3,3}, [in,out,binary,stream])) of
				{'EXIT', ebadf} ->
					io:format("failed to open fd 3 in read/write mode\n"),
					halt(1);
				DataChan -> main(Module, User, Class, Service, Dict, DataChan)
			end
	end.

usage() ->
	io:format("usage: login_style [-v name=value] [-s service] username class\n"),
	io:format("intended to be used with the BSD auth framework\n"),
	halt(1).

-define(OP_PUTC,0).
-define(OP_MOVE,1).
-define(OP_INSC,2).
-define(OP_DELC,3).
-define(OP_BEEP,4).

getpw() ->
	case io:setopts([binary, {echo, false}]) of
		ok ->
			PwLine = io:get_line(<<"Password: ">>),
			ok = io:setopts([binary, {echo, true}]),
			io:format("\n"),
			[Pw | _] = binary:split(PwLine, <<"\n">>),
			Pw;
		_ ->
			Port = open_port({spawn, 'tty_sl -e'}, [binary, eof]),
			port_command(Port, <<?OP_PUTC, "Password:">>),
			receive
				{Port, {data, PwLine}} ->
					[Pw | _] = binary:split(PwLine, <<"\n">>),
					port_command(Port, <<?OP_PUTC, $\n>>),
					port_close(Port),
					Pw
			end
	end.

read_nullstring(Port) -> read_nullstring(Port, <<>>).
read_nullstring(Port, SoFar) ->
	case binary:split(SoFar, <<0>>) of
		[Str, Rest] -> {Str, Rest};
		_ ->
			receive
				{Port, {data, D}} ->
					read_nullstring(Port, <<SoFar/binary, D/binary>>)
			end
	end.

main(Mod, User, Class, login, Dict, DataChan) ->
	Pw = getpw(),
	Resp = Mod:verify(User, Pw, Class, Dict),
	respond(Resp, DataChan);

main(Mod, User, Class, challenge, Dict, DataChan) ->
	port_command(DataChan, <<"reject silent\n">>),
	halt(0);

main(Mod, User, Class, response, Dict, DataChan) ->
	{_Challenge, Rem} = read_nullstring(DataChan),
	{PwLine, _} = read_nullstring(DataChan, Rem),
	[Pw | _] = binary:split(PwLine, <<"\n">>),
	Resp = Mod:verify(User, Pw, Class, Dict),
	respond(Resp, DataChan).

respond(true, DataChan) ->
	port_command(DataChan, <<"authorize\n">>),
	halt(0);
respond(false, DataChan) ->
	port_command(DataChan, <<"reject\n">>),
	halt(0);
respond({Type, Opts}, DataChan) ->
	lists:foreach(fun
		({setenv, K, V}) ->
			port_command(DataChan, iolist_to_binary(
				io_lib:format("setenv ~s ~s\n", [K, V])));
		({unsetenv, K}) ->
			port_command(DataChan, iolist_to_binary(
				io_lib:format("unsetenv ~s\n", [K])));
		({error, Err}) ->
			port_command(DataChan, iolist_to_binary(
				io_lib:format("value errormsg ~s\n", [Err])));
		(_) -> ok
	end, Opts),
	case Type of
		true ->
			case lists:member(secure, Opts) of
				true -> port_command(DataChan, <<"authorize secure\n">>);
				false -> port_command(DataChan, <<"authorize\n">>)
			end;
		false ->
			case lists:member(silent, Opts) of
				true -> port_command(DataChan, <<"reject silent\n">>);
				false -> port_command(DataChan, <<"reject\n">>)
			end
	end,
	halt(0).
