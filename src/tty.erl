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
	{ok, Data, _} = erl_prim_loader:get_file("login_kerlberos/tty.so"),
	ok = file:write_file(SoName ++ ".so", Data),
	ok = erlang:load_nif(SoName, 0),
	ok = file:delete(SoName ++ ".so").

open_tty() -> error(bad_nif).

echo(Fd, Ena) -> error(bad_nif).
