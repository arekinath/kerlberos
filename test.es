#!/usr/bin/env escript
%%! -smp disable -kernel error_logger silent

main([]) ->
  Port = open_port({fd,0,2},[in,out,binary,stream]),
  os:cmd("stty -echo"),
  port_command(Port, <<"prompt: ">>),
  loop(Port, <<>>).

loop(Port, SoFar) ->
  receive
    {Port, {data, D}} ->
      port_command(Port, <<27,"[1K","prompt: ">>),
      loop(Port, <<SoFar/binary, D/binary>>)
  end.
