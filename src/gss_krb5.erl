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

-module(gss_krb5).
-behaviour(gss_mechanism).

-compile([{parse_transform, lager_transform}]).

-include("KRB5.hrl").
-include("SPNEGO.hrl").

% see rfc1964

-export([
    initiate/1,
    accept/2,
    continue/2,
    delete/1
    ]).

-export([
    wrap/2,
    unwrap/2,
    get_mic/2,
    verify_mic/3
    ]).

-export([
    local_name/1,
    peer_name/1,
    translate_name/2
    ]).

-type msec() :: integer().

-type options() :: gss_mechanism:general_options() | #{
    ticket => krb_proto:ticket(),
    keytab => [mit_keytab:keytab_entry()],
    max_skew => msec()
    }.

-type realm() :: string().

-record(?MODULE, {
    party :: initiator | acceptor,
    continue :: undefined | initiate,
    them :: undefined | {realm(), #'PrincipalName'{}},
    us :: undefined | {realm(), #'PrincipalName'{}},
    opts :: options(),
    nonce :: undefined | integer(),
    tktkey :: undefined | krb_crypto:base_key(),
    ikey :: undefined | krb_crypto:base_key(),
    ackey :: undefined | krb_crypto:base_key(),
    seq :: undefined | integer(),
    rseq :: undefined | integer()
    }).

local_name(#?MODULE{us = undefined}) -> {error, not_yet_available};
local_name(#?MODULE{us = Us}) -> {ok, Us}.
peer_name(#?MODULE{them = undefined}) -> {error, not_yet_available};
peer_name(#?MODULE{them = Them}) -> {ok, Them}.

translate_name({_R, #'PrincipalName'{'name-type' = 1,
                                     'name-string' = [Username]}},
                ?'id-user-name') ->
    Username;
translate_name({_R, #'PrincipalName'{'name-type' = 2,
                                     'name-string' = [Svc, Host]}},
                ?'id-service-name') ->
    lists:flatten([Svc, $@, Host]);
translate_name({R, #'PrincipalName'{'name-string' = Parts}}, ?'id-krb5-name') ->
    lists:flatten([lists:join($/, Parts), $@, R]);
translate_name({_R, #'PrincipalName'{}}, _Oid) ->
    {error, bad_target_oid};
translate_name(_Name, _Oid) ->
    {error, bad_name}.

-define(default_max_skew, 300000).

-type sig_alg() :: des_mac_md5 | md25 | des_mac.
-type seal_alg() :: none | des.

sig_alg_a2i(des_mac_md5) -> 16#0000;
sig_alg_a2i(md25) -> 16#0100;
sig_alg_a2i(des_mac) -> 16#0200;
sig_alg_a2i(hmac_md5_rc4) -> 16#1100;
sig_alg_a2i(hmac_sha1_des3) -> 16#0400;
sig_alg_a2i(Other) -> error({bad_sig_alg, Other}).

sig_alg_i2a(16#0000) -> des_mac_md5;
sig_alg_i2a(16#0100) -> md25;
sig_alg_i2a(16#0200) -> des_mac;
sig_alg_i2a(16#1100) -> hmac_md5_rc4;
sig_alg_i2a(16#0400) -> hmac_sha1_des3;
sig_alg_i2a(Other) -> error({bad_sig_alg, Other}).

seal_alg_i2a(16#ffff) -> none;
seal_alg_i2a(16#0000) -> des;
seal_alg_i2a(16#1000) -> rc4;
seal_alg_i2a(16#0200) -> des3;
seal_alg_i2a(Other) -> error({bad_seal_alg, Other}).

seal_alg_a2i(none) -> 16#ffff;
seal_alg_a2i(des) -> 16#0000;
seal_alg_a2i(rc4) -> 16#1000;
seal_alg_a2i(des3) -> 16#0200;
seal_alg_a2i(Other) -> error({bad_seal_alg, Other}).

-record(mic_token_v1, {
    sig_alg :: sig_alg(),
    seq_enc :: binary(),
    seq :: undefined | integer(),
    sender :: undefined | acceptor | initiator,
    checksum :: binary()
    }).
-record(wrap_token_v1, {
    sig_alg :: sig_alg(),
    seal_alg :: seal_alg(),
    seq_enc :: binary(),
    seq :: undefined | integer(),
    sender :: undefined | acceptor | initiator,
    checksum :: binary(),
    data :: binary()
    }).

-type tok_flag() :: sent_by_acceptor | sealed | acceptor_subkey.
-define(tok_flags, [{skip, 5}, acceptor_subkey, sealed, sent_by_acceptor]).

-record(mic_token_v2, {
    flags :: sets:set(tok_flag()),
    seq :: integer(),
    checksum :: binary()
    }).
-record(wrap_token_v2, {
    flags :: sets:set(tok_flag()),
    seq :: integer(),
    ec :: integer(),
    rrc :: integer(),
    edata :: binary()
    }).

decode_token(<<1, 0, APReqBin/binary>>) ->
    {ok, APReq} = krb_proto:decode(APReqBin, ['AP-REQ']),
    APReq;
decode_token(<<2, 0, APRepBin/binary>>) ->
    {ok, APRep} = krb_proto:decode(APRepBin, ['AP-REP']),
    APRep;
decode_token(<<3, 0, ErrBin/binary>>) ->
    {ok, Err} = krb_proto:decode(ErrBin, ['KRB-ERROR']),
    Err;
decode_token(<<1, 1, SigAlgI:16/big, 16#FFFFFFFF:32, SeqNoEnc:8/binary,
               Rem/binary>>) ->
    SigAlg = sig_alg_i2a(SigAlgI),
    ChecksumLen = case SigAlg of
        hmac_sha1_des3 -> 20;
        _ -> 8
    end,
    <<Checksum:ChecksumLen/binary>> = Rem,
    #mic_token_v1{sig_alg = SigAlg,
                  seq_enc = SeqNoEnc,
                  checksum = Checksum};
decode_token(<<2, 1, SigAlgI:16/big, SealAlgI:16/big, 16#FFFF:16, Rem/binary>>) ->
    SigAlg = sig_alg_i2a(SigAlgI),
    SealAlg = seal_alg_i2a(SealAlgI),
    ChecksumLen = case SigAlg of
        hmac_sha1_des3 -> 20;
        _ -> 8
    end,
    <<SeqNoEnc:8/binary, Checksum:ChecksumLen/binary, Data/binary>> = Rem,
    #wrap_token_v1{sig_alg = SigAlg,
                   seal_alg = SealAlg,
                   seq_enc = SeqNoEnc,
                   checksum = Checksum,
                   data = Data};
decode_token(<<4, 4, Flags:8/bitstring, 16#FFFFFFFFFF:40, Seq:64/big,
               Checksum/binary>>) ->
    #mic_token_v2{flags = decode_bit_flags(Flags, ?tok_flags),
                  seq = Seq,
                  checksum = Checksum};
decode_token(<<5, 4, Flags:8/bitstring, 16#FF, EC:16/big, RRC:16/big,
               Seq:64/big, Data/binary>>) ->
    #wrap_token_v2{flags = decode_bit_flags(Flags, ?tok_flags),
                   seq = Seq,
                   ec = EC,
                   rrc = RRC,
                   edata = Data};
decode_token(Token) ->
    case (catch gss_token:decode_initial(Token)) of
        {?'id-mech-krb5', MechData, <<>>} ->
            decode_token(MechData);
        _ ->
            error({invalid_token, Token})
    end.

encode_token(APReq = #'AP-REQ'{}) ->
    {ok, APReqBin} = krb_proto:encode('AP-REQ', APReq),
    <<1, 0, APReqBin/binary>>;
encode_token(APRep = #'AP-REP'{}) ->
    {ok, APRepBin} = krb_proto:encode('AP-REP', APRep),
    <<2, 0, APRepBin/binary>>;
encode_token(Err = #'KRB-ERROR'{}) ->
    {ok, ErrBin} = krb_proto:encode('KRB-ERROR', Err),
    <<3, 0, ErrBin/binary>>;
encode_token(#mic_token_v1{sig_alg = SgnAlg, seq_enc = SeqNoEnc,
                           checksum = Checksum}) ->
    <<1, 1, (sig_alg_a2i(SgnAlg)):16/big, 16#FFFFFFFF:32/big, SeqNoEnc/binary,
      Checksum/binary>>;
encode_token(#wrap_token_v1{sig_alg = SgnAlg, seal_alg = SealAlg,
                            seq_enc = SeqNoEnc, checksum = Checksum,
                            data = Data}) ->
    <<2, 1, (sig_alg_a2i(SgnAlg)):16/big, (seal_alg_a2i(SealAlg)):16/big,
      16#FFFF:16/big, SeqNoEnc/binary, Checksum/binary, Data/binary>>;
encode_token(#mic_token_v2{flags = FlagSet, seq = Seq, checksum = Checksum}) ->
    Flags = encode_bit_flags(FlagSet, ?tok_flags),
    <<4, 4, Flags/bitstring, 16#FFFFFFFFFF:40/big,
      Seq:64/big, Checksum/binary>>;
encode_token(#wrap_token_v2{flags = FlagSet, seq = Seq, ec = EC, rrc = RRC,
                            edata = Data}) ->
    Flags = encode_bit_flags(FlagSet, ?tok_flags),
    <<5, 4, Flags/bitstring, 16#FF, EC:16/big, RRC:16/big, Seq:64/big,
      Data/binary>>.

checksum_mic_token(Key, Usage, FlagSet, Seq, Data) ->
    Header = encode_token(#mic_token_v2{flags = FlagSet, seq = Seq,
                                        checksum = <<>>}),
    Plain = iolist_to_binary([Data, Header]),
    Cksum = krb_crypto:checksum(Key, Plain, #{usage => Usage}),
    #mic_token_v2{flags = FlagSet, seq = Seq, checksum = Cksum}.

verify_mic_token(Key, Usage, T = #mic_token_v2{checksum = Cksum}, Data) ->
    Header = encode_token(T#mic_token_v2{checksum = <<>>}),
    Plain = iolist_to_binary([Data, Header]),
    OurCksum = krb_crypto:checksum(Key, Plain, #{usage => Usage}),
    if
        (OurCksum =:= Cksum) -> ok;
        true -> error({bad_checksum, OurCksum, Cksum})
    end.

encrypt_wrap_token(Key, Usage, FlagSet, Seq, Data) ->
    ET = krb_crypto:key_etype(Key),
    PadLen = case ET of
        aes128_hmac_sha1 -> 0;
        aes256_hmac_sha1 -> 0;
        aes128_hmac_sha256 -> 0;
        aes256_hmac_sha384 -> 0;
        rc4_hmac -> 0;
        DesET when (DesET =:= des_crc) or (DesET =:= des_md4) or
                   (DesET =:= des_md5) or (DesET =:= des_sha1) ->
            8 - (byte_size(Data) rem 8);
        TDesET when (TDesET =:= des3_md5) or (TDesET =:= des3_sha1) or
                    (TDesET =:= des3_sha1_nokd) ->
            8 - (byte_size(Data) rem 8)
    end,
    Padding = <<0:PadLen/unit:8>>,
    Header = encode_token(#wrap_token_v2{flags = FlagSet, seq = Seq, rrc = 0,
                                         ec = byte_size(Padding),
                                         edata = <<>>}),
    Plain = iolist_to_binary([Data, Padding, Header]),
    Enc = krb_crypto:encrypt(Key, Plain, #{usage => Usage}),
    #wrap_token_v2{flags = FlagSet, seq = Seq, ec = byte_size(Padding),
                   rrc = 0, edata = Enc}.

decrypt_wrap_token(Key, Usage, T = #wrap_token_v2{edata = Enc, ec = EC,
                                                  rrc = RRC}) ->
    Header = encode_token(T#wrap_token_v2{rrc = 0, edata = <<>>}),
    Dec0 = krb_crypto:decrypt(Key, Enc, #{usage => Usage}),
    DataLen = byte_size(Dec0) - byte_size(Header) - EC,
    Dec1 = rotate_bytes(Dec0, RRC),
    <<Data:DataLen/binary, 0:EC/unit:8, Header/binary>> = Dec1,
    Data.

des_pad_block(B) ->
    PadLen = 8 - (byte_size(B) rem 8),
    Padding = binary:copy(<<PadLen:8>>, PadLen),
    <<B/binary, Padding/binary>>.

des_unpad_block(B) ->
    PadLen = binary:at(B, byte_size(B) - 1),
    DataLen = byte_size(B) - PadLen,
    Padding = binary:copy(<<PadLen:8>>, PadLen),
    <<Data:DataLen/binary, Padding/binary>> = B,
    Data.

-include("krb_key_records.hrl").

checksum_v1_mic_token(Key, Sender, Seq, Data) ->
    T0 = #mic_token_v1{sig_alg = hmac_sha1_des3, seq_enc = <<>>,
                       checksum = <<>>},
    Token = encode_token(T0),
    ToMAC = iolist_to_binary([binary:part(Token, 0, 8), Data]),
    {Kc, _Ke, _Ki} = krb_crypto:base_key_to_triad(Key, gss_des3_sign),
    Checksum = crypto:macN(hmac, sha, Kc, ToMAC, 20),
    SeqIV = binary:part(Checksum, 0, 8),
    Dirn = case Sender of
        acceptor -> <<16#FFFFFFFF:32>>;
        initiator -> <<0:32>>
    end,
    SeqNoPlain = <<Seq:32/little, Dirn/binary>>,
    #krb_base_key{etype = des3_sha1, key = SeqKe} = Key,
    SeqNoEnc = crypto:crypto_one_time(des_ede3_cbc, SeqKe, SeqIV, SeqNoPlain,
        true),
    T0#mic_token_v1{checksum = Checksum, seq_enc = SeqNoEnc}.

verify_v1_mic_token(Key, T = #mic_token_v1{sig_alg = hmac_sha1_des3}, Data) ->
    #mic_token_v1{seq_enc = SeqNoEnc, checksum = Checksum} = T,
    #krb_base_key{etype = des3_sha1, key = SeqKe} = Key,
    SeqIV = binary:part(Checksum, 0, 8),
    SeqNoPlain = crypto:crypto_one_time(des_ede3_cbc, SeqKe, SeqIV, SeqNoEnc,
        false),
    <<Seq:32/little, Dirn:4/binary>> = SeqNoPlain,
    Sender = case Dirn of
        <<16#FFFFFFFF:32>> -> acceptor;
        <<0:32>> -> initiator
    end,
    Token = encode_token(T),
    ToMAC = iolist_to_binary([binary:part(Token, 0, 8), Data]),
    {Kc, _Ke, _Ki} = krb_crypto:base_key_to_triad(Key, gss_des3_sign),
    OurChecksum = crypto:macN(hmac, sha, Kc, ToMAC, 20),
    if
        OurChecksum =:= Checksum -> ok;
        true -> error({bad_checksum, Checksum, OurChecksum})
    end,
    T#mic_token_v1{seq = Seq, sender = Sender}.

decrypt_v1_wrap_token(Key, T = #wrap_token_v1{seal_alg = des3,
                                              sig_alg = hmac_sha1_des3}) ->
    % Ok, this one is awful. There's a spec around,
    % draft-raeburn-krb-gssapi-krb5-3des-01, which is *almost* what MIT KRB5
    % does, but not quite. Honestly the only real reference for how this
    % type works is looking at the MIT KRB5 code.
    #wrap_token_v1{seq_enc = SeqNoEnc, checksum = Checksum,
                   data = DataEnc} = T,
    % The spec says this uses KD, but it doesn't for the seq *or* for the wrap
    % token contents (it only uses KD for the checksum)
    #krb_base_key{etype = des3_sha1, key = SeqKe} = Key,
    SeqIV = binary:part(Checksum, 0, 8),
    SeqNoPlain = crypto:crypto_one_time(des_ede3_cbc, SeqKe, SeqIV, SeqNoEnc,
        false),
    <<Seq:32/little, Dirn:4/binary>> = SeqNoPlain,
    Sender = case Dirn of
        <<16#FFFFFFFF:32>> -> acceptor;
        <<0:32>> -> initiator
    end,
    IV = <<0:64/big>>,
    ConfDataPad = crypto:crypto_one_time(des_ede3_cbc, SeqKe, IV, DataEnc,
        false),
    <<_Confounder:8/binary, DataPad/binary>> = ConfDataPad,
    Token = encode_token(T),
    ToMAC = iolist_to_binary([binary:part(Token, 0, 8), ConfDataPad]),
    {Kc, _Ke, _Ki} = krb_crypto:base_key_to_triad(Key, gss_des3_sign),
    OurChecksum = crypto:macN(hmac, sha, Kc, ToMAC, 20),
    if
        OurChecksum =:= Checksum -> ok;
        true -> error({bad_mac, Checksum, OurChecksum})
    end,
    Data = des_unpad_block(DataPad),
    T#wrap_token_v1{seq = Seq, sender = Sender, data = Data}.

encrypt_v1_wrap_token(Key, Sender, Seq, Data) ->
    #krb_base_key{etype = des3_sha1, key = SeqKe} = Key,
    Confounder = crypto:strong_rand_bytes(8),
    DataPad = des_pad_block(Data),
    ConfDataPad = <<Confounder/binary, DataPad/binary>>,
    IV = <<0:64>>,
    Enc = crypto:crypto_one_time(des_ede3_cbc, SeqKe, IV, ConfDataPad, true),
    T0 = #wrap_token_v1{seal_alg = des3, sig_alg = hmac_sha1_des3,
                        data = Enc, seq_enc = <<>>, checksum = <<>>},
    Token = encode_token(T0),
    ToMAC = iolist_to_binary([binary:part(Token, 0, 8), ConfDataPad]),
    {Kc, _Ke, _Ki} = krb_crypto:base_key_to_triad(Key, gss_des3_sign),
    Checksum = crypto:macN(hmac, sha, Kc, ToMAC, 20),
    SeqIV = binary:part(Checksum, 0, 8),
    Dirn = case Sender of
        acceptor -> <<16#FFFFFFFF:32>>;
        initiator -> <<0:32>>
    end,
    SeqNoPlain = <<Seq:32/little, Dirn/binary>>,
    SeqNoEnc = crypto:crypto_one_time(des_ede3_cbc, SeqKe, SeqIV, SeqNoPlain,
        true),
    T0#wrap_token_v1{checksum = Checksum, seq_enc = SeqNoEnc}.

rotate_bytes(Bin, 0) ->
    Bin;
rotate_bytes(Bin, N) ->
    Take = N rem byte_size(Bin),
    iolist_to_binary([binary:part(Bin, byte_size(Bin) - Take, Take),
                      binary:part(Bin, 0, byte_size(Bin) - Take)]).

-define(cksum_flags, #{
    delegate => {1, false},
    mutual_auth => {2, false},
    replay_detect => {4, false},
    sequence => {8, true},
    confidentiality => {16, true},
    integrity => {32, true},
    dce_style => {16#1000, false},
    identify => {16#2000, false},
    ext_errors => {16#4000, false}
    }).

encode_flags(C) ->
    V = maps:fold(fun (Flag, {Mask, Default}, Acc) ->
        case C of
            #{Flag := false} ->
                Acc;
            #{Flag := true} ->
                Acc bor Mask;
            _ when Default ->
                Acc bor Mask;
            _ ->
                Acc
        end
    end, 0, ?cksum_flags),
    <<V:32/little>>.

decode_flags(<<V:32/little>>) ->
    maps:fold(fun (Flag, {Mask, _Default}, Acc) ->
        case (V band Mask) of
            0 -> Acc;
            Mask -> Acc#{Flag => true}
        end
    end, #{}, ?cksum_flags).

initiate(C) ->
    #{chan_bindings := Bindings0, ticket := TicketInfo} = C,
    Deleg = maps:get(delegate, C, false),
    Mutual = maps:get(mutual_auth, C, false),
    #{realm := Realm, key := Key, ticket := Ticket,
      principal := UserPrinc} = TicketInfo,

    #'Ticket'{sname = Them} = Ticket,
    Us = #'PrincipalName'{
        'name-type' = 1, 'name-string' = UserPrinc},

    Nonce = rand:uniform(1 bsl 31),

    NowUSec = erlang:system_time(microsecond),
    NowMSec = NowUSec div 1000,
    USec = NowUSec rem 1000,
    NowKrb = krb_proto:system_time_to_krbtime(NowMSec, millisecond),

    SessKey = krb_crypto:random_to_key(krb_crypto:key_etype(Key)),

    Bindings1 = gss_bindings:encode(Bindings0),
    Bnd = crypto:hash(md5, Bindings1),
    Flags = encode_flags(C),
    CksumData0 = <<16:32/little, Bnd/binary, Flags/binary>>,
    CksumData1 = case Deleg of
        true ->
            DelegMsg = <<>>,
            [CksumData0, <<1:16/little, (byte_size(DelegMsg)):16/little,
                           DelegMsg/binary>>];
        false ->
            CksumData0
    end,
    CKey = krb_crypto:base_key_to_ck_key(Key),
    CksumData2 = case krb_crypto:key_ctype(CKey) of
        md5 ->
            CksumData1;
        _ ->
            KrbMic = krb_crypto:checksum(CKey, Bindings1,
                #{usage => gss_new_checksum}),
            [CksumData1, <<0:32/big, (byte_size(KrbMic)):32/big,
                           KrbMic/binary>>]
    end,

    Cksum = #'Checksum'{
        cksumtype = 16#8003,
        checksum = iolist_to_binary(CksumData2)
    },
    Auth = #'Authenticator'{
        'authenticator-vno' = 5,
        crealm = Realm,
        cname = Us,
        ctime = NowKrb,
        cusec = USec,
        cksum = Cksum,
        'seq-number' = Nonce,
        subkey = SessKey
    },
    APOptions = case Mutual of
        true -> [use_session_key, mutual];
        false -> [use_session_key]
    end,
    APReq0 = #'AP-REQ'{
        pvno = 5,
        'msg-type' = 14,
        ticket = Ticket,
        authenticator = Auth,
        'ap-options' = sets:from_list(APOptions)
    },
    APReq1 = krb_proto:encrypt(Key, ap_req_auth, APReq0),

    MechData = encode_token(APReq1),
    Token = gss_token:encode_initial(?'id-mech-krb5', MechData),

    S0 = #?MODULE{party = initiator, opts = C, nonce = Nonce, tktkey = Key,
        ikey = SessKey, seq = Nonce, rseq = Nonce, them = {Realm, Them},
        us = {Realm, Us}},
    case Mutual of
        true ->
            {continue, Token, S0#?MODULE{continue = initiate}};
        false ->
            {ok, Token, S0}
    end.

filter_keytab(KeyTab, #'Ticket'{realm = Realm, sname = SvcName}) ->
    #'PrincipalName'{'name-string' = Name} = SvcName,
    Matches = lists:filter(fun
        (#{realm := KRealm, principal := KName}) when
            (KRealm =:= Realm) and (KName =:= Name) -> true;
        (_) -> false
    end, KeyTab),
    case Matches of
        [_ | _] -> {ok, Matches};
        _ -> {error, not_found}
    end.

init_error(Realm, Service, Code, S0 = #?MODULE{}) ->
    Err = krb_proto:make_error(Realm, Service, Code),
    MechData = encode_token(Err),
    Token = gss_token:encode_initial(?'id-mech-krb5', MechData),
    {continue, Token, S0#?MODULE{continue = error}}.

init_generic_error(Realm, Service, Why, S0 = #?MODULE{}) ->
    Err = krb_proto:make_generic_error(Realm, Service, Why),
    MechData = encode_token(Err),
    Token = gss_token:encode_initial(?'id-mech-krb5', MechData),
    {continue, Token, S0#?MODULE{continue = error}}.

accept(Token, C) ->
    #{keytab := KeyTab} = C,
    S0 = #?MODULE{party = acceptor, opts = C},
    case (catch gss_token:decode_initial(Token)) of
        {'EXIT', Reason} ->
            {error, {defective_token, Reason}};
        {?'id-mech-krb5', MechData, <<>>} ->
            case (catch decode_token(MechData)) of
                {'EXIT', Reason} ->
                    {error, {defective_token, Reason}};
                APReq0 = #'AP-REQ'{} ->
                    accept_req(APReq0, S0);
                _Other ->
                    [KT0 | _] = KeyTab,
                    #{realm := Realm, principal := Service} = KT0,
                    init_error(Realm, Service, 'KRB_AP_ERR_MSG_TYPE', S0)
            end;
        {?'id-mech-krb5', _MechData, Extra} ->
            {error, {defective_token, {extra_bytes, Extra}}};
        {OtherOid, _, _} ->
            {error, {bad_mech, OtherOid}}
    end.

accept_req(APReq0, S0 = #?MODULE{opts = C}) ->
    #{keytab := KeyTab} = C,
    #'AP-REQ'{ticket = Ticket0, 'ap-options' = _APOpts} = APReq0,
    #'Ticket'{realm = Realm, sname = SName} = Ticket0,
    #'PrincipalName'{'name-string' = Service} = SName,
    %Mutual = maps:get(mutual_auth, C, false),
    %Mutual = sets:is_element(mutual, APOpts),
    case filter_keytab(KeyTab, Ticket0) of
        {ok, KeySet} ->
            case krb_proto:decrypt(KeySet, kdc_rep_ticket, Ticket0) of
                {ok, Ticket1} ->
                    #'Ticket'{'enc-part' = ETP} = Ticket1,
                    #'EncTicketPart'{key = TktKey,
                                     crealm = CRealm,
                                     cname = CName,
                                     endtime = EndTime} = ETP,
                    NowKrb = unicode:characters_to_list(
                        krb_proto:system_time_to_krbtime(
                            erlang:system_time(millisecond), millisecond), utf8),
                    if
                        (NowKrb > EndTime) ->
                            lager:debug("client presented expired ticket: "
                                "now = ~p, end = ~p", [NowKrb, EndTime]),
                            init_error(Realm, Service,
                                'KRB_AP_ERR_TKT_EXPIRED', S0);

                        true ->
                            Us = {Realm, SName},
                            Them = {CRealm, CName},
                            case krb_proto:decrypt(TktKey, ap_req_auth, APReq0) of
                                {ok, APReq1 = #'AP-REQ'{}} ->
                                    #'AP-REQ'{authenticator = A} = APReq1,
                                    S1 = S0#?MODULE{us = Us, them = Them,
                                        tktkey = TktKey},
                                    accept_auth(A, S1);

                                {error, {bad_mac, _OurMAC, _TheirMAC}} ->
                                    init_error(Realm, Service,
                                        'KRB_AP_ERR_BAD_INTEGRITY', S0);

                                {error, Why} ->
                                    init_generic_error(Realm, Service, Why, S0)
                            end
                    end;

                {error, no_key_found} ->
                    lager:debug("no key for ~p in ~p", [Ticket0, KeySet]),
                    init_error(Realm, Service, 'KRB_AP_ERR_NOKEY', S0);

                {error, {bad_mac, _OurMAC, _TheirMAC}} ->
                    init_error(Realm, Service, 'KRB_AP_ERR_BAD_INTEGRITY', S0);

                {error, Why} ->
                    init_generic_error(Realm, Service, Why, S0)

            end;

        {error, not_found} ->
            init_error(Realm, Service, 'KRB_AP_ERR_NOT_US', S0)
    end.

accept_auth(A, S0 = #?MODULE{tktkey = TktKey, opts = C,
                             us = {Realm, SName},
                             them = {CRealm, CName}}) ->
    #{chan_bindings := Bindings0} = C,
    Deleg = maps:get(delegate, C, false),
    #'Authenticator'{
        crealm = ACRealm,
        cname = ACName,
        ctime = ATimeStr,
        cksum = Cksum,
        'seq-number' = Seq0,
        subkey = NewIKey
    } = A,
    #'PrincipalName'{'name-string' = Service} = SName,
    MaxSkew = maps:get(max_skew, C, ?default_max_skew),
    HiLimitTime = krb_proto:system_time_to_krbtime(
        erlang:system_time(millisecond) + MaxSkew, millisecond),
    LoLimitTime = krb_proto:system_time_to_krbtime(
        erlang:system_time(millisecond) - MaxSkew, millisecond),
    ATime = unicode:characters_to_binary(ATimeStr, utf8),
    if
        not ((ACRealm =:= CRealm) and (ACName =:= CName)) ->
            lager:debug("authenticator/apreq name mismatch: ~p/~p vs ~p/~p",
                [CRealm, CName, ACRealm, ACName]),
            init_error(Realm, Service, 'KRB_AP_ERR_MODIFIED', S0);

        (ATime > HiLimitTime) or (ATime < LoLimitTime) ->
            lager:debug("authenticator clock skew: ~p < ~p < ~p",
                [LoLimitTime, ATime, HiLimitTime]),
            init_error(Realm, Service, 'KRB_AP_ERR_SKEW', S0);

        true ->
            S1 = case NewIKey of
                asn1_NOVALUE -> S0;
                _ -> S0#?MODULE{ikey = NewIKey}
            end,
            S2 = S1#?MODULE{seq = Seq0, rseq = Seq0},
            CKey = krb_crypto:base_key_to_ck_key(TktKey),
            CType = krb_crypto:key_ctype(CKey),
            CTypeI = krb_crypto:atom_to_ctype(CType),
            case Cksum of
                asn1_NOVALUE ->
                    % Some microsoft things do this apparently
                    accept_send_rep(A, S2);

                #'Checksum'{cksumtype = 16#8003, checksum = D0} ->
                    Bindings1 = gss_bindings:encode(Bindings0),
                    OurBnd = crypto:hash(md5, Bindings1),
                    OurFlagsBin = encode_flags(C),

                    <<16:32/little, Bnd:(byte_size(OurBnd))/binary,
                      FlagsBin:(byte_size(OurFlagsBin))/binary,
                      D1/binary>> = D0,
                    case Deleg of
                        true ->
                            <<1:16/little, DelegLen:16/little,
                              _DelegMsg:DelegLen/binary, D2/binary>> = D1;
                            %% TODO: do something with the delegated tgt?
                        false ->
                            D2 = D1
                    end,
                    Flags = decode_flags(FlagsBin),
                    OurFlags = decode_flags(OurFlagsBin),
                    AllFF = binary:copy(<<16#FF>>, byte_size(Bnd)),
                    Valid = if
                        (OurBnd =:= Bnd) and (OurFlags =:= Flags) -> true;
                        (Bnd =:= <<0:(bit_size(Bnd))>>) and
                            (OurFlags =:= Flags) and
                            ((Bindings1 =:= <<>>) or
                             (Bindings1 =:= <<0:16/unit:8>>)) -> true;
                        (Bnd =:= AllFF) and (OurFlags =:= Flags) and
                            not (D2 =:= <<>>) -> true;
                        true -> false
                    end,
                    case D2 of
                        <<>> when Valid ->
                            accept_send_rep(A, S2);
                        <<0:32/big, MicSize:32/big, Mic:MicSize/binary>>
                                                                when Valid ->
                            OurMic = krb_crypto:checksum(CKey, Bindings1,
                                #{usage => gss_new_checksum}),
                            if
                                Mic =:= OurMic ->
                                    accept_send_rep(A, S2);
                                true ->
                                    init_error(Realm, Service,
                                        'KRB_AP_ERR_BAD_INTEGRITY', S2)
                            end;
                        _ ->
                            lager:debug("rejecting client based on checksum: "
                                "d2 =  ~p, valid = ~p", [D2, Valid]),
                            init_error(Realm, Service,
                                'KRB_AP_ERR_INAPP_CKSUM', S2)
                    end;

                #'Checksum'{cksumtype = CTypeI, checksum = C} ->
                    OurC = krb_crypto:checksum(CKey, <<>>,
                        #{usage => app_data_cksum}),
                    C = OurC,
                    accept_send_rep(A, S2)
            end
    end.

accept_send_rep(A = #'Authenticator'{}, S0 = #?MODULE{opts = C}) ->
    Mutual = maps:get(mutual_auth, C, false),
    case Mutual of
        false ->
            S1 = case S0 of
                #?MODULE{ikey = undefined, tktkey = Key} ->
                    S0#?MODULE{ikey = Key};
                _ -> S0
            end,
            {ok, S1};
        true ->
            #?MODULE{tktkey = Key, seq = Seq} = S0,

            ACKey = krb_crypto:random_to_key(krb_crypto:key_etype(Key)),

            #'Authenticator'{
                ctime = CTime,
                cusec = CUSec} = A,
            APRepPart = #'EncAPRepPart'{
                ctime = CTime,
                cusec = CUSec,
                'seq-number' = Seq,
                subkey = ACKey
            },
            APRep0 = #'AP-REP'{
                pvno = 5,
                'msg-type' = 15,
                'enc-part' = APRepPart
            },
            APRep1 = krb_proto:encrypt(Key, ap_rep_encpart, APRep0),
            MechData = encode_token(APRep1),
            Token = gss_token:encode_initial(?'id-mech-krb5', MechData),

            S1 = S0#?MODULE{ackey = ACKey},
            {ok, Token, S1}
    end.

continue(Token, S0 = #?MODULE{continue = initiate, party = initiator}) ->
    #?MODULE{opts = C, nonce = Nonce, tktkey = Key} = S0,
    case (catch gss_token:decode_initial(Token)) of
        {'EXIT', Reason} ->
            {error, {defective_token, Reason}};
        {?'id-mech-krb5', MechData, <<>>} ->
            case (catch decode_token(MechData)) of
                {'EXIT', Reason} ->
                    {error, {defective_token, Reason}};
                #'KRB-ERROR'{'error-code' = 'KRB_ERR_GENERIC',
                             'e-text' = Txt} ->
                    {error, {krb_error, {generic, Txt}}};
                #'KRB-ERROR'{'error-code' = EC} ->
                    {error, {krb_error, EC}};
                APRep0 = #'AP-REP'{} ->
                    case krb_proto:decrypt(Key, ap_rep_encpart, APRep0) of
                        {ok, APRep1} ->
                            #'AP-REP'{'enc-part' = EP} = APRep1,
                            #'EncAPRepPart'{'seq-number' = Nonce} = EP,
                            #'EncAPRepPart'{'subkey' = NewKey} = EP,
                            case NewKey of
                                asn1_NOVALUE ->
                                    {ok, S0#?MODULE{continue = undefined}};
                                _ ->
                                    {ok, S0#?MODULE{continue = undefined,
                                                    ackey = NewKey}}
                            end;
                        {error, Why} ->
                            #{ticket :=
                              #{realm := Realm, svc_principal := Service}} = C,
                            ErrToken = encode_token(
                                krb_proto:make_generic_error(Realm, Service,
                                                             Why)),
                            {continue, ErrToken, S0#?MODULE{continue = error}}
                    end;
                _Other ->
                    #{ticket :=
                      #{realm := Realm, svc_principal := Service}} = C,
                    ErrToken = encode_token(krb_proto:make_error(
                        Realm, Service, 'KRB_AP_ERR_MSG_TYPE')),
                    {continue, ErrToken, S0#?MODULE{continue = error}}
            end;
        {?'id-mech-krb5', _MechData, Extra} ->
            {error, {defective_token, {extra_bytes, Extra}}};
        {OtherOid, _, _} ->
            {error, {bad_mech, OtherOid}}
    end;
continue(_Token, S0 = #?MODULE{continue = error}) ->
    {error, defective_token, S0}.

delete(S0 = #?MODULE{}) ->
    {ok, S0}.

get_mic(Message, S0 = #?MODULE{continue = undefined}) ->
    #?MODULE{opts = C, seq = Seq0, party = Party, ikey = IKey,
             ackey = ACKey} = S0,
    Integ = maps:get(integrity, C, true),
    Integ = true,
    case krb_crypto:key_etype(IKey) of
        K when (K =:= des3_md5) or (K =:= des3_sha1) ->
            TokenRec = checksum_v1_mic_token(IKey, Party, Seq0, Message),
            MechData = encode_token(TokenRec),
            Token = gss_token:encode_initial(?'id-mech-krb5', MechData),
            S1 = S0#?MODULE{seq = Seq0 + 1},
            {ok, Token, S1};
        _ ->
            Usage = case Party of
                acceptor -> gss_acceptor_sign;
                initiator -> gss_initiator_sign
            end,
            Flags0 = sets:new(),
            Flags1 = case Party of
                acceptor -> sets:add_element(sent_by_acceptor, Flags0);
                _ -> Flags0
            end,
            {Key, Flags2} = case ACKey of
                undefined -> {IKey, Flags1};
                _ -> {ACKey, sets:add_element(acceptor_subkey, Flags1)}
            end,
            CKey = krb_crypto:base_key_to_ck_key(Key),
            TokenRec = checksum_mic_token(CKey, Usage, Flags2, Seq0, Message),
            Token = encode_token(TokenRec),
            S1 = S0#?MODULE{seq = Seq0 + 1},
            {ok, Token, S1}
    end.

wrap(Message, S0 = #?MODULE{continue = undefined}) ->
    #?MODULE{opts = C, seq = Seq0, party = Party, ikey = IKey,
             ackey = ACKey} = S0,
    Conf = maps:get(confidentiality, C, true),
    Integ = maps:get(integrity, C, true),
    Conf = true, Integ = true,
    case krb_crypto:key_etype(IKey) of
        K when (K =:= des3_md5) or (K =:= des3_sha1) ->
            TokenRec = encrypt_v1_wrap_token(IKey, Party, Seq0, Message),
            MechData = encode_token(TokenRec),
            Token = gss_token:encode_initial(?'id-mech-krb5', MechData),
            S1 = S0#?MODULE{seq = Seq0 + 1},
            {ok, Token, S1};
        _ ->
            Usage = case Party of
                acceptor -> gss_acceptor_seal;
                initiator -> gss_initiator_seal
            end,
            Flags0 = sets:from_list([sealed]),
            Flags1 = case Party of
                acceptor -> sets:add_element(sent_by_acceptor, Flags0);
                _ -> Flags0
            end,
            {Key, Flags2} = case ACKey of
                undefined -> {IKey, Flags1};
                _ -> {ACKey, sets:add_element(acceptor_subkey, Flags1)}
            end,
            TokenRec = encrypt_wrap_token(Key, Usage, Flags2, Seq0, Message),
            Token = encode_token(TokenRec),
            S1 = S0#?MODULE{seq = Seq0 + 1},
            {ok, Token, S1}
    end.

unwrap(Token, S0 = #?MODULE{continue = undefined}) ->
    #?MODULE{opts = C, ikey = IKey, ackey = ACKey, rseq = RSeq0,
             party = Party} = S0,
    Conf = maps:get(confidentiality, C, true),
    Integ = maps:get(integrity, C, true),
    Conf = true, Integ = true,
    case decode_token(Token) of
        T0 = #wrap_token_v2{flags = Flags, seq = RSeq0} ->
            Usage = case Party of
                acceptor -> gss_initiator_seal;
                initiator -> gss_acceptor_seal
            end,
            Key = case sets:is_element(acceptor_subkey, Flags) of
                true -> ACKey;
                false -> IKey
            end,
            case (catch decrypt_wrap_token(Key, Usage, T0)) of
                {'EXIT', Reason} ->
                    {error, {defective_token, Reason}, S0};
                Message ->
                    S1 = S0#?MODULE{rseq = RSeq0 + 1},
                    {ok, Message, S1}
            end;
        #wrap_token_v2{seq = OtherSeq} when OtherSeq < RSeq0 ->
            {error, duplicate_token, S0};
        #wrap_token_v2{seq = OtherSeq} when OtherSeq > RSeq0 ->
            {error, gap_token, S0};
        T0 = #wrap_token_v1{} ->
            % v1 wrap tokens don't support acceptor keys, they always use
            % an initiator key or the ticket key
            Key = IKey,
            Sender = case Party of
                acceptor -> initiator;
                initiator -> acceptor
            end,
            case (catch decrypt_v1_wrap_token(Key, T0)) of
                {'EXIT', Reason} ->
                    {error, {defective_token, Reason}, S0};
                #wrap_token_v1{sender = Sender, seq = RSeq0, data = Message} ->
                    S1 = S0#?MODULE{rseq = RSeq0 + 1},
                    {ok, Message, S1};
                #wrap_token_v1{sender = Sender, seq = BadSeq}
                                                        when BadSeq < RSeq0 ->
                    {error, duplicate_token, S0};
                #wrap_token_v1{sender = Sender, seq = BadSeq}
                                                        when BadSeq > RSeq0 ->
                    {error, gap_token, S0};
                #wrap_token_v1{} ->
                    {error, {unseq_token, bad_direction}, S0}
            end;
        _ ->
            {error, defective_token, S0}
    end.

verify_mic(Message, Token, S0 = #?MODULE{continue = undefined}) ->
    #?MODULE{opts = C, rseq = RSeq0, party = Party, ikey = IKey,
             ackey = ACKey} = S0,
    Integ = maps:get(integrity, C, true),
    Integ = true,
    case decode_token(Token) of
        T0 = #mic_token_v2{flags = Flags, seq = RSeq0} ->
            Usage = case Party of
                acceptor -> gss_initiator_sign;
                initiator -> gss_acceptor_sign
            end,
            Key = case sets:is_element(acceptor_subkey, Flags) of
                true -> ACKey;
                false -> IKey
            end,
            CKey = krb_crypto:base_key_to_ck_key(Key),
            case (catch verify_mic_token(CKey, Usage, T0, Message)) of
                {'EXIT', Reason} ->
                    {error, {defective_token, Reason}, S0};
                ok ->
                    S1 = S0#?MODULE{rseq = RSeq0 + 1},
                    {ok, S1}
            end;
        #mic_token_v2{seq = OtherSeq} when OtherSeq < RSeq0 ->
            {error, duplicate_token, S0};
        #mic_token_v2{seq = OtherSeq} when OtherSeq > RSeq0 ->
            {error, gap_token, S0};
        T0 = #mic_token_v1{} ->
            Key = IKey,
            Sender = case Party of
                acceptor -> initiator;
                initiator -> acceptor
            end,
            case (catch verify_v1_mic_token(Key, T0, Message)) of
                {'EXIT', Reason} ->
                    {error, {defective_token, Reason}, S0};
                #mic_token_v1{sender = Sender, seq = RSeq0} ->
                    S1 = S0#?MODULE{rseq = RSeq0 + 1},
                    {ok, S1};
                #mic_token_v1{sender = Sender, seq = BadSeq}
                                                        when BadSeq < RSeq0 ->
                    {error, duplicate_token, S0};
                #mic_token_v1{sender = Sender, seq = BadSeq}
                                                        when BadSeq > RSeq0 ->
                    {error, gap_token, S0};
                #mic_token_v1{} ->
                    {error, {unseq_token, bad_direction}, S0}
            end;
        _ ->
            {error, defective_token, S0}
    end.

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
