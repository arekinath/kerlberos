%% kerlberos
%%
%% Copyright 2021 Alex Wilson <alex@uq.edu.au>
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

-module(krb_proto).

-compile([{parse_transform, lager_transform}]).

-include("krb_key_records.hrl").
-include("KRB5.hrl").

-export([
    datetime_to_krbtime/1,
    system_time_to_krbtime/2,
    encode_kdc_flags/1,
    decode_kdc_flags/1,
    encode_ticket_flags/1,
    decode_ticket_flags/1,
    decode/2,
    encode/2,
    decrypt/3
    ]).

-export_type([
    ticket/0
    ]).

-type ticket() :: #'Ticket'{}.

-define(kdc_flags, [
    skip,forwardable,forwarded,proxiable,
    proxy,allow_postdate,postdated,skip,
    renewable,pk_cross,skip,hw_auth,
    {skip,3},canonicalize,
    {skip,8},
    {skip,2},disable_transited,renewable_ok,
    enc_tkt_in_skey,skip,renew,validate]).

-define(ticket_flags, [
    skip,forwardable,forwarded,proxiable,
    proxy,allow_postdate,postdated,invalid,
    renewable,initial,pre_auth,hw_auth,
    transited,delegate,skip,skip,
    anonymous,skip,skip,skip,
    {skip,12}]).

-type kdc_flag() :: forwardable | forwarded | proxiable | proxy |
    allow_postdate | postdated | renewable | pk_cross | hw_auth |
    canonicalize | disable_transited | renewable_ok | enc_tkt_in_skey |
    renew | validate.
-type ticket_flag() :: forwardable | forwarded | proxiable | proxy |
    allow_postdate | postdated | invalid | renewable | initial | pre_auth |
    hw_auth | transited | delegate | anonymous.

-export_type([kdc_flag/0, ticket_flag/0]).

-spec encode_kdc_flags(sets:set(kdc_flag())) -> bitstring().
encode_kdc_flags(FlagSet) ->
    encode_bit_flags(FlagSet, ?kdc_flags).
-spec decode_kdc_flags(bitstring()) -> sets:set(kdc_flag()).
decode_kdc_flags(Bitstring) ->
    decode_bit_flags(Bitstring, ?kdc_flags).
-spec encode_ticket_flags(sets:set(ticket_flag())) -> bitstring().
encode_ticket_flags(FlagSet) ->
    encode_bit_flags(FlagSet, ?ticket_flags).
-spec decode_ticket_flags(bitstring()) -> sets:set(ticket_flag()).
decode_ticket_flags(Bitstring) ->
    decode_bit_flags(Bitstring, ?ticket_flags).

decode(_Data, []) -> {error, not_decoded};
decode(Data, [NextType | Rest]) ->
    case 'KRB5':decode(NextType, Data) of
        {ok, Record0, Leftover} ->
            case Leftover of
                <<>> -> ok;
                _ ->
                    lager:debug("garbage after asn.1 decoding (~p): ~p",
                        [NextType, Leftover])
            end,
            Record1 = post_decode(Record0),
            {ok, Record1};
        _ ->
            decode(Data, Rest)
    end.

post_decode(Pa = #'PA-DATA'{'padata-type' = 11, 'padata-value' = V0}) ->
    case 'KRB5':decode('ETYPE-INFO', V0) of
        {ok, V1, <<>>} -> Pa#'PA-DATA'{'padata-value' = V1};
        _ -> Pa
    end;
post_decode(Pa = #'PA-DATA'{'padata-type' = 19, 'padata-value' = V0}) ->
    case 'KRB5':decode('ETYPE-INFO2', V0) of
        {ok, V1, <<>>} -> Pa#'PA-DATA'{'padata-value' = V1};
        _ -> Pa
    end;
post_decode(E = #'KRB-ERROR'{'error-code' = I}) when is_integer(I) ->
    IC = krb_errors:err_to_atom(I),
    post_decode(E#'KRB-ERROR'{'error-code' = IC});
post_decode(E = #'KRB-ERROR'{'e-data' = D0}) when is_binary(D0) ->
    case 'KRB5':decode('METHOD-DATA', D0) of
        {ok, D1, <<>>} ->
            D2 = [post_decode(Pa) || Pa <- D1],
            E#'KRB-ERROR'{'e-data' = D2};
        _ ->
            E
    end;
post_decode(R = #'KDC-REP'{'enc-part' = EP}) ->
    R#'KDC-REP'{'enc-part' = post_decode(EP)};
post_decode(EP = #'EncryptedData'{etype = ETI}) when is_integer(ETI) ->
    ET = krb_crypto:etype_to_atom(ETI),
    post_decode(EP#'EncryptedData'{etype = ET});
post_decode(R = #'EncKDCRepPart'{flags = FlagsBin}) when is_binary(FlagsBin) ->
    Flags = decode_bit_flags(FlagsBin, ?ticket_flags),
    post_decode(R#'EncKDCRepPart'{flags = Flags});
post_decode(R = #'EncKDCRepPart'{key = EK}) ->
    R#'EncKDCRepPart'{key = post_decode(EK)};
post_decode(#'EncryptionKey'{keytype = ETI, keyvalue = KV}) when is_integer(ETI) ->
    ET = krb_crypto:etype_to_atom(ETI),
    #krb_base_key{etype = ET, key = KV};
post_decode(S) -> S.

-type encrypted_reply() :: #'KDC-REP'{'enc-part' :: #'EncryptedData'{}}.
-type reply() :: #'KDC-REP'{'enc-part' :: #'EncKDCRepPart'{}}.

-spec decrypt(krb_crypto:base_key(), krb_crypto:usage(), encrypted_reply()) -> {ok, reply()} | {error, term()}.
decrypt(K, Usage, R0 = #'KDC-REP'{'enc-part' = EP}) ->
    #krb_base_key{etype = EType} = K,
    #'EncryptedData'{etype = EType, cipher = CT} = EP,
    case (catch krb_crypto:decrypt(K, CT, #{usage => Usage})) of
        {'EXIT', Why} ->
            {error, Why};
        Plain ->
            case (catch inner_decode_tgs_or_as(Plain)) of
                {'EXIT', Why} ->
                    {error, {inner_decode, Why}};
                Inner ->
                    R1 = R0#'KDC-REP'{'enc-part' = Inner},
                    {ok, R1}
            end
    end.

-spec inner_decode_tgs_or_as(binary()) -> #'EncKDCRepPart'{}.
inner_decode_tgs_or_as(Bin) ->
    case 'KRB5':decode('EncTGSRepPart', Bin) of
        {ok, EncPart, <<>>} ->
            post_decode(EncPart);
        _ ->
            inner_decode_as(Bin)
    end.

inner_decode_as(Bin) ->
    case 'KRB5':decode('EncASRepPart', Bin) of
        {ok, EncPart, <<>>} ->
            post_decode(EncPart);

        _ ->
            % HACK ALERT
            % microsoft's older krb5 implementations often chop off the front
            % of the EncASRepPart. what you get is just its innards starting
            % with an un-tagged EncryptionKey
            {ok, #'EncryptionKey'{}, B} = 'KRB5':decode('EncryptionKey', Bin),

            % reconstruct the front part that's missing -- first, the context
            % #0 tag for EncryptionKey
            {LenBytes, _} = asn1_encode_length(byte_size(Bin) - byte_size(B)),
            All = <<1:1, 0:1, 1:1, 0:5, (list_to_binary(LenBytes))/binary,
                    Bin/binary>>,
            % then the sequence tag to go on the very front
            {LenBytes2, _} = asn1_encode_length(byte_size(All)),
            Plain2 = <<0:1, 0:1, 1:1, 16:5,
                       (list_to_binary(LenBytes2))/binary, All/binary>>,

            % don't bother reconstructing the application tag for EncASRepPart,
            % just decode it here as a plain EncKDCRepPart
            {ok, EncPart, <<>>} = 'KRB5':decode('EncKDCRepPart', Plain2),
            post_decode(EncPart)
    end.

asn1_encode_length(L) when L =< 127 ->
    {[L],1};
asn1_encode_length(L) ->
    Oct = minimum_octets(L),
    Len = length(Oct),
    if
        Len =< 126 ->
            {[128 bor Len|Oct],Len + 1};
        true ->
            exit({error,{asn1,too_long_length_oct,Len}})
    end.

minimum_octets(0, Acc) ->
    Acc;
minimum_octets(Val, Acc) ->
    minimum_octets(Val bsr 8, [Val band 255|Acc]).

minimum_octets(Val) ->
    minimum_octets(Val, []).

encode(Type, Data) ->
    'KRB5':encode(Type, Data).

-type krbtime() :: binary().

-spec datetime_to_krbtime(datetime:datetime()) -> krbtime().
datetime_to_krbtime({{Y, M, D}, {Hr, Min, Sec}}) ->
    iolist_to_binary(io_lib:format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
        [Y, M, D, Hr, Min, Sec])).

-type unit() :: atom().
-spec system_time_to_krbtime(integer(), unit()) -> krbtime().
system_time_to_krbtime(V, U) ->
    UT = calendar:system_time_to_universal_time(V, U),
    datetime_to_krbtime(UT).

-type flag() :: atom().
-type bit_flags() :: [skip | {skip, integer()} | flag()].

-spec decode_bit_flags(bitstring(), bit_flags()) -> sets:set(flag()).
decode_bit_flags(<<>>, _) -> sets:new();
decode_bit_flags(Bits, [{skip,N} | RestAtoms]) ->
    <<_Flags:N, Rest/bitstring>> = Bits,
    decode_bit_flags(Rest, RestAtoms);
decode_bit_flags(<<_Flag:1, Rest/bitstring>>, [skip | RestAtoms]) ->
    decode_bit_flags(Rest, RestAtoms);
decode_bit_flags(Bits, [{FlagAtom, Width} | RestAtoms]) ->
    <<Flag:Width/little, Rest/bitstring>> = Bits,
    case Flag of
        0 -> decode_bit_flags(Rest, RestAtoms);
        1 -> sets:add_element(FlagAtom, decode_bit_flags(Rest, RestAtoms));
        N -> sets:add_element({FlagAtom, N}, decode_bit_flags(Rest, RestAtoms))
    end;
decode_bit_flags(<<Flag:1, Rest/bitstring>>, [FlagAtom | RestAtoms]) ->
    case Flag of
        1 -> sets:add_element(FlagAtom, decode_bit_flags(Rest, RestAtoms));
        0 -> decode_bit_flags(Rest, RestAtoms)
    end.

-spec encode_bit_flags(sets:set(flag()), bit_flags()) -> bitstring().
encode_bit_flags(_FlagSet, []) -> <<>>;
encode_bit_flags(FlagSet, [{skip, N} | RestAtoms]) ->
    RestBin = encode_bit_flags(FlagSet, RestAtoms),
    <<0:N, RestBin/bitstring>>;
encode_bit_flags(FlagSet, [skip | RestAtoms]) ->
    RestBin = encode_bit_flags(FlagSet, RestAtoms),
    <<0:1, RestBin/bitstring>>;
encode_bit_flags(FlagSet, [{FlagAtom, Width} | RestAtoms]) ->
    RestBin = encode_bit_flags(FlagSet, RestAtoms),
    case sets:is_element(FlagAtom, FlagSet) of
        true -> <<1:Width/little, RestBin/bitstring>>;
        false -> <<0:Width/little, RestBin/bitstring>>
    end;
encode_bit_flags(FlagSet, [FlagAtom | RestAtoms]) ->
    RestBin = encode_bit_flags(FlagSet, RestAtoms),
    case sets:is_element(FlagAtom, FlagSet) of
        true -> <<1:1, RestBin/bitstring>>;
        false -> <<0:1, RestBin/bitstring>>
    end.
