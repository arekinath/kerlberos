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

%% @doc Functions for decoding Microsoft PACs inside a Kerberos ticket.
-module(krb_ms_pac).

-export([decode/1, decode_ticket/1]).

%% @headerfile "ms_pac.hrl"
-include("ms_pac.hrl").
-include("KRB5.hrl").

-export_type([pac/0, sid/0, sid_attr/0, pac_buffer/0]).

-type sid_attr() :: mandatory | default | enabled | owner | resource.
-type sid() :: #sid{}.

-type pac() :: #pac{}.

-type pac_unknown() :: #pac_unknown{}.
-type pac_client_info() :: #pac_client_info{}.
-type pac_upn_dns() :: #pac_upn_dns{}.
-type pac_logon_info() :: #pac_logon_info{}.
-type pac_buffer() :: pac_unknown() | pac_client_info() |
    pac_upn_dns() | pac_logon_info().

%% @doc Extracts and decodes a PAC from a given Kerberos ticket.
-spec decode_ticket(#'Ticket'{}) ->
    {ok, pac()} | {error, no_pac} | {error, {bad_pac, term()}}.
decode_ticket(#'Ticket'{'enc-part' = ETP = #'EncTicketPart'{}}) ->
    #'EncTicketPart'{'authorization-data' = ADs} = ETP,
    find_pac_ad(ADs).

find_pac_ad(asn1_NOVALUE) ->
    {error, no_pac};
find_pac_ad([]) ->
    {error, no_pac};
find_pac_ad([#'AuthorizationData_SEQOF'{'ad-type' = 128} = AD0 | _]) ->
    #'AuthorizationData_SEQOF'{'ad-data' = D0} = AD0,
    case (catch decode(D0)) of
        {'EXIT', Why} ->
            {error, {bad_pac, Why}};
        Pac = #pac{} ->
            {ok, Pac}
    end;
find_pac_ad([#'AuthorizationData_SEQOF'{'ad-type' = 1} = AD0 | Rest]) ->
    #'AuthorizationData_SEQOF'{'ad-data' = D0} = AD0,
    case krb_proto:decode(D0, ['AuthorizationData']) of
        {ok, InnerAD} ->
            find_pac_ad(Rest ++ InnerAD);
        Err ->
            Err
    end;
find_pac_ad([_ | Rest]) ->
    find_pac_ad(Rest).

%% @doc Decodes a PAC from raw bytes. Throws errors on invalid input.
-spec decode(binary()) -> pac().
decode(Bin = <<Count:32/little, Version:32/little, Rem/binary>>) ->
    Bufs = decode_info_bufs(Count, Rem, Bin),
    #pac{version = Version, buffers = Bufs}.

decode_info_bufs(0, _, _Bin) -> [];
decode_info_bufs(N, <<Type:32/little, Size:32/little, Offset:64/little, Rem/binary>>, Bin) ->
    <<_:Offset/binary, Segment:Size/binary, _/binary>> = Bin,
    Rec = case Type of
        16#01 -> decode_logon_info(Segment, Bin);
        16#0a -> decode_client_info(Segment, Bin);
        16#0c -> decode_upn_dns(Segment, Bin);
        % 16#0e -> decode_device_info(Segment, Bin);
        % 16#0d -> decode_client_claims(Segment, Bin);
        % 16#0f -> decode_device_claims(Segment, Bin);
        _ -> #pac_unknown{type = Type, data = Segment}
    end,
    [Rec | decode_info_bufs(N - 1, Rem, Bin)].

decode_client_info(Segment, _Bin) ->
    <<TgtTime:64/little, NameLen:16/little, Name:NameLen/binary>> = Segment,
    #pac_client_info{
        tgt_time = TgtTime,
        name = unicode:characters_to_binary(Name, {utf16, little}, utf8)
    }.

decode_upn_dns(Segment, _Bin) ->
    <<UpnLen:16/little, UpnOffset:16/little, DnsNameLen:16/little,
      DnsNameOffset:16/little, _Flags:32/little, _/binary>> =Segment,
    <<_:UpnOffset/binary, Upn:UpnLen/binary, _/binary>> = Segment,
    <<_:DnsNameOffset/binary, DnsName:DnsNameLen/binary, _/binary>> = Segment,
    #pac_upn_dns{
        upn = unicode:characters_to_binary(Upn, {utf16, little}, utf8),
        dns_name = unicode:characters_to_binary(DnsName, {utf16, little}, utf8)
    }.

decode_logon_info(Segment, _Bin) ->
    S0 = ms_rpce:start(Segment),
    {LogonTime, S1} = ms_rpce:read(filetime, S0),
    {LogoffTime, S2} = ms_rpce:read(filetime, S1),
    {KickOffTime, S3} = ms_rpce:read(filetime, S2),
    {PasswordLastSet, S4} = ms_rpce:read(filetime, S3),
    {PasswordCanChange, S5} = ms_rpce:read(filetime, S4),
    {PasswordMustChange, S6} = ms_rpce:read(filetime, S5),
    {EffNamePtr, S7} = ms_rpce:read(rpc_unicode_string, S6),
    {FullNamePtr, S8} = ms_rpce:read(rpc_unicode_string, S7),
    {LogonScriptPtr, S9} = ms_rpce:read(rpc_unicode_string, S8),
    {ProfilePathPtr, S10} = ms_rpce:read(rpc_unicode_string, S9),
    {HomeDirPtr, S11} = ms_rpce:read(rpc_unicode_string, S10),
    {HomeDirDrivePtr, S12} = ms_rpce:read(rpc_unicode_string, S11),
    {LogonCount, S13} = ms_rpce:read(ushort, S12),
    {BadPasswordCount, S14} = ms_rpce:read(ushort, S13),
    {UserId, S15} = ms_rpce:read(ulong, S14),
    {_PrimaryGroupId, S16} = ms_rpce:read(ulong, S15),
    {_GroupCount, S17} = ms_rpce:read(ulong, S16),
    {GroupsPtr, S18} = ms_rpce:read({pointer, {array, group_membership}}, S17),
    {_UserFlags, S19} = ms_rpce:read(ulong, S18),
    {_SessKey, S20} = ms_rpce:read(user_session_key, S19),
    {LogonServerPtr, S21} = ms_rpce:read(rpc_unicode_string, S20),
    {LogonDomainNamePtr, S22} = ms_rpce:read(rpc_unicode_string, S21),
    {LogonDomainIdPtr, S23} = ms_rpce:read({pointer, sid}, S22),
    {_Reserved1, S24} = ms_rpce:read(ulong, S23),
    {_Reserved2, S25} = ms_rpce:read(ulong, S24),
    {_UAC, S26} = ms_rpce:read(ulong, S25),
    {_SubAuthStatus, S27} = ms_rpce:read(ulong, S26),
    {_LastSuccessfulILogon, S28} = ms_rpce:read(filetime, S27),
    {_LastFailedILogon, S29} = ms_rpce:read(filetime, S28),
    {_FailedILogonCount, S30} = ms_rpce:read(ulong, S29),
    {_Reserved3, S31} = ms_rpce:read(ulong, S30),
    {_SidCount, S32} = ms_rpce:read(ulong, S31),
    {SidPtr, S33} = ms_rpce:read({pointer, {array, kerb_sid_and_attributes}}, S32),
    {_RscGroupDomainSid, S34} = ms_rpce:read({pointer, sid}, S33),
    {_RscGroupCount, S35} = ms_rpce:read(ulong, S34),
    {_RscGroupPtr, S36} = ms_rpce:read({pointer, {array, group_membership}}, S35),
    SFinal = ms_rpce:finish(S36),

    Sids0 = ms_rpce:get_ptr(SidPtr, SFinal),
    Sids1 = [S#sid_and_attributes{
        sid = ms_rpce:get_ptr(SidPtr, SFinal)}
            || S = #sid_and_attributes{sid_ptr = ASidPtr} <- Sids0,
               ASidPtr =:= SidPtr],

    #pac_logon_info{
        times = #{
            logon => LogonTime,
            logoff => LogoffTime,
            kickoff => KickOffTime,
            pw_last_set => PasswordLastSet,
            pw_can_change => PasswordCanChange,
            pw_must_change => PasswordMustChange
        },
        ename = ms_rpce:get_ptr(EffNamePtr, SFinal),
        fname = ms_rpce:get_ptr(FullNamePtr, SFinal),
        logon_script = ms_rpce:get_ptr(LogonScriptPtr, SFinal),
        profile_path = ms_rpce:get_ptr(ProfilePathPtr, SFinal),
        homedir = ms_rpce:get_ptr(HomeDirPtr, SFinal),
        home_drive = ms_rpce:get_ptr(HomeDirDrivePtr, SFinal),
        logon_count = LogonCount,
        bad_pw_count = BadPasswordCount,
        userid = UserId,
        groups = ms_rpce:get_ptr(GroupsPtr, SFinal),
        logon_server = ms_rpce:get_ptr(LogonServerPtr, SFinal),
        domain = ms_rpce:get_ptr(LogonDomainNamePtr, SFinal),
        domain_sid = ms_rpce:get_ptr(LogonDomainIdPtr, SFinal),
        sids = Sids1
    }.
