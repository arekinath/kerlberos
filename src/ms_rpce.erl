%% kerlberos
%%
%% Copyright 2020 Alex Wilson <alex@uq.edu.au>
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

-module(ms_rpce).

-export([start/1, finish/1, read/2, get_ptr/2]).

-include("ms_pac.hrl").
-export_type([rpce_ptr/0, rpce_state/0]).

-record(rpce_ptr, {tag :: binary()}).

-record(rpce_state, {
    r :: binary(),
    off = 0 :: integer(),
    deferred = gb_sets:empty() :: gb_sets:set(#rpce_ptr{}),
    ptrtype = #{} :: #{#rpce_ptr{} => atom()},
    ptrdata = #{} :: #{#rpce_ptr{} => term()}
}).

-opaque rpce_ptr() :: #rpce_ptr{}.
-opaque rpce_state() :: #rpce_state{}.

-spec start(binary()) -> rpce_state().
start(Rem0) ->
    <<Version, Endian, CHLen:16/little, Rem1/binary>> = Rem0,
    Version = 1,
    Endian = 16#10,
    CHLenRem = CHLen - 4,
    <<_CHPad:CHLenRem/binary,
      ObjBufLen:32/little, _:4/binary,
      Rem2:(ObjBufLen)/binary>> = Rem1,
    <<_:32, Rem3/binary>> = Rem2,
    #rpce_state{r = Rem3, off = 0}.

-spec attrs_to_atoms(integer()) -> [sid_attr()].
attrs_to_atoms(N) ->
    <<_:2, E:1, _:25, D:1, C:1, B:1, A:1>> = <<N:32/big>>,
    case A of 1 -> [mandatory]; _ -> [] end ++
    case B of 1 -> [default]; _ -> [] end ++
    case C of 1 -> [enabled]; _ -> [] end ++
    case D of 1 -> [owner]; _ -> [] end ++
    case E of 1 -> [resource]; _ -> [] end.

-spec padding_size(integer(), integer()) -> integer().
padding_size(PrimSize, Off) ->
    Rem = Off rem PrimSize,
    case Rem of
        0 -> 0;
        _ ->
            %io:format("padding ~p\n", [PrimSize - Rem]),
            PrimSize - Rem
    end.

-spec read(term(), rpce_state()) -> {term(), rpce_state()}.
read(filetime, S0 = #rpce_state{r = Rem0, off = Off}) ->
    Padding = padding_size(4, Off),
    <<_:Padding/binary, V:64/little, Rem1/binary>> = Rem0,
    S1 = S0#rpce_state{r = Rem1, off = Off + Padding + 8},
    case V of
        16#7fffffffffffffff ->
            {never, S1};
        0 ->
            {null, S1};
        _ ->
            USec = (V - 116444736000000000) div 10,
            {{USec, microsecond}, S1}
    end;

read({unicode_string, Len, _MaxLen}, S0 = #rpce_state{r = Rem0, off = Off}) ->
    Padding = padding_size(4, Off),
    <<_:Padding/binary,
      _MaxLength:32/little, 0:32/little, Length:32/little,
      Rem1/binary>> = Rem0,
    ActualLen = Length * 2,
    <<Data:ActualLen/binary, Rem2/binary>> = Rem1,
    <<StringData:Len/binary, _/binary>> = Data,
    S1 = S0#rpce_state{r = Rem2, off = Off + Padding + 12 + ActualLen},
    Str = unicode:characters_to_binary(StringData,
        {utf16, little}, utf8),
    {Str, S1};

read(rpc_unicode_string, S0 = #rpce_state{off = Off}) ->
    Padding = padding_size(4, Off),
    #rpce_state{r = Rem0, deferred = Def0, ptrtype = Typ0} = S0,
    <<_:Padding/binary,
      Len:16/little, MaxLen:16/little, Referent:4/binary,
      Rem1/binary>> = Rem0,
    Ptr = #rpce_ptr{tag = Referent},
    S1 = case Typ0 of
        #{Ptr := {unicode_string, Len, MaxLen}} ->
            S0#rpce_state{r = Rem1, off = Off + Padding + 8};
        #{Ptr := _} ->
            error(type_confusion);
        _ ->
            Def1 = gb_sets:add(Ptr, Def0),
            Typ1 = Typ0#{Ptr => {unicode_string, Len, MaxLen}},
            S0#rpce_state{
                r = Rem1, deferred = Def1, ptrtype = Typ1,
                off = Off + Padding + 8
            }
    end,
    {Ptr, S1};

read(sid, S0 = #rpce_state{r = Rem0, off = Off}) ->
    Padding = padding_size(4, Off),
    case Rem0 of
        <<_:Padding/binary,
          SubAuthCount:32/little,
          1, SubAuthCount, IdentifierAuth:48/big,
          Rem1/binary>> -> ok;
        <<_:Padding/binary,
          1, SubAuthCount, IdentifierAuth:48/big,
          Rem1/binary>> -> ok
    end,
    SubAuthLen = SubAuthCount * 4,
    <<SubAuthsBin:SubAuthLen/binary, Rem2/binary>> = Rem1,
    S1 = S0#rpce_state{r = Rem2, off = Off + Padding + 12 + SubAuthLen},
    {SubAuths, _} = lists:foldl(fun (_I, {Acc0, ARem0}) ->
        <<Next:32/little, ARem1/binary>> = ARem0,
        {[Next | Acc0], ARem1}
    end, {[], SubAuthsBin}, lists:seq(1, SubAuthCount)),
    Sid = #sid{revision = 1, identifier_auth = IdentifierAuth,
        sub_auths = lists:reverse(SubAuths)},
    {Sid, S1};

read(kerb_sid_and_attributes, S0 = #rpce_state{}) ->
    {SidPtr, S1} = read({pointer,  sid}, S0),
    {Attrs, S2} = read(ulong, S1),
    {#sid_and_attributes{sid_ptr = SidPtr,
        attrs = attrs_to_atoms(Attrs)}, S2};

read(ushort, S0 = #rpce_state{r = Rem0, off = Off}) ->
    Padding = padding_size(2, Off),
    <<_:Padding/binary, V:16/little, Rem1/binary>> = Rem0,
    {V, S0#rpce_state{r = Rem1, off = Off + Padding + 2}};

read(ulong, S0 = #rpce_state{r = Rem0, off = Off}) ->
    Padding = padding_size(4, Off),
    <<_:Padding/binary, V:32/little, Rem1/binary>> = Rem0,
    {V, S0#rpce_state{r = Rem1, off = Off + Padding + 4}};

read({array, ulong}, S0 = #rpce_state{}) ->
    {Bins, S1} = read({array, conformant, 4}, S0),
    {[V || <<V:32/little>> <- Bins], S1};

read(group_membership, S0 = #rpce_state{}) ->
    {Rid, S1} = read(ulong, S0),
    {Attrs, S2} = read(ulong, S1),
    {#group_membership{rid = Rid,
        attrs = attrs_to_atoms(Attrs)}, S2};

read({array, Type}, S0 = #rpce_state{}) ->
    {Count, S1} = read(ulong, S0),
    {Res, S2} = lists:foldl(fun (_I, {Acc0, SS0}) ->
        {SAA, SS1} = read(Type, SS0),
        {[SAA | Acc0], SS1}
    end, {[], S1}, lists:seq(1, Count)),
    {lists:reverse(Res), S2};

read({array, conformant, MemberSize}, S0 = #rpce_state{r = Rem0, off = Off}) ->
    Padding = padding_size(4, Off),
    <<_:Padding/binary, Count:32/little, Rem1/binary>> = Rem0,
    Length = Count * MemberSize,
    <<Data:Length/binary, Rem2/binary>> = Rem1,
    {Datas, <<>>} = lists:foldl(fun (_I, {Acc0, ARem0}) ->
        <<Next:MemberSize/binary, ARem1/binary>> = ARem0,
        {[Next | Acc0], ARem1}
    end, {[], Data}, lists:seq(1, Count)),
    S1 = S0#rpce_state{r = Rem2, off = Off + Padding + 12 + Length},
    {lists:reverse(Datas), S1};

read({pointer, UnderType}, S0 = #rpce_state{off = Off}) ->
    #rpce_state{r = Rem0, deferred = Def0, ptrtype = Typ0} = S0,
    Padding = padding_size(4, Off),
    <<_:Padding/binary, Referent:4/binary, Rem1/binary>> = Rem0,
    Ptr = #rpce_ptr{tag = Referent},
    S1 = case {Referent, Typ0} of
        {<<0,0,0,0>>, _} ->
            S0#rpce_state{r = Rem1, off = Off + Padding + 4};
        {_, #{Ptr := UnderType}} ->
            S0#rpce_state{r = Rem1, off = Off + Padding + 4};
        {_, #{Ptr := Other}} ->
            error({type_confusion, Ptr, Other, UnderType});
        {_, _} ->
            Def1 = gb_sets:add(Ptr, Def0),
            Typ1 = Typ0#{Ptr => UnderType},
            S0#rpce_state{
                r = Rem1, deferred = Def1, ptrtype = Typ1,
                off = Off + Padding + 4
            }
    end,
    {Ptr, S1};

read(user_session_key, S0 = #rpce_state{r = Rem0, off = Off}) ->
    Padding = padding_size(8, Off),
    <<_:Padding/binary, V:16/binary, Rem1/binary>> = Rem0,
    {V, S0#rpce_state{r = Rem1, off = Off + Padding + 16}}.

finish(S0 = #rpce_state{deferred = Defs0, ptrtype = Types}) ->
    case gb_sets:is_empty(Defs0) of
        true ->
            #rpce_state{r = Rem} = S0,
            RemSize = bit_size(Rem),
            <<0:RemSize>> = Rem,
            S0;
        false ->
            {Ptr, Defs1} = gb_sets:take_smallest(Defs0),
            S1 = S0#rpce_state{deferred = Defs1},
            #{Ptr := Type} = Types,
            %io:format("reading deferred ~p, ref ~p\n", [Type, Ptr]),
            %io:format(" @ data ~p\n", [S1#rpce_state.r]),
            {V, S2} = read(Type, S1),
            %io:format(" => ~p\n", [V]),
            #rpce_state{ptrdata = Data0} = S2,
            Data1 = Data0#{Ptr => V},
            S3 = S2#rpce_state{ptrdata = Data1},
            finish(S3)
    end.

get_ptr(#rpce_ptr{tag = <<0,0,0,0>>}, _) -> null;
get_ptr(Ptr = #rpce_ptr{}, #rpce_state{ptrdata = PtrData}) ->
    #{Ptr := Data} = PtrData,
    Data.
