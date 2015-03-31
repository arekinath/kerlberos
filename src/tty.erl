%% kerlberos
%%
%% Copyright (c) 2015, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(tty).

-export([open_tty/0, load_from_zip/0, echo/2]).

load_from_zip() ->
	SoName = "/tmp/tty-" ++ os:getpid(),
	PathToMe = filename:split(code:which(tty)),
	BasePath = lists:sublist(PathToMe, length(PathToMe) - 3),
	Path = filename:join(BasePath ++ ["tty.so"]),
	{ok, Data, _} = erl_prim_loader:get_file(Path),
	ok = file:write_file(SoName ++ ".so", Data),
	ok = erlang:load_nif(SoName, 0),
	ok = file:delete(SoName ++ ".so").

open_tty() -> error(bad_nif).

echo(Fd, Ena) -> error(bad_nif).