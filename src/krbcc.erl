%% kerlberos
%%
%% Copyright (c) 2015, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(krbcc).

-include("KRB5.hrl").

-callback init(Opts :: [{atom(), term()}]) -> {ok, State :: term()}.
-callback terminate(State :: term()) -> ignored.
