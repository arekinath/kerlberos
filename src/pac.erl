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

-module(pac).

-export([decode/1]).

-include("pac.hrl").

-spec decode(binary()) -> #pac{}.
decode(Bin = <<Count:32/little, Version:32/little, Rem/binary>>) ->
    Bufs = decode_info_bufs(Count, Rem, Bin),
    #pac{version = Version, buffers = Bufs}.

decode_info_bufs(0, _, Bin) -> [];
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
      DnsNameOffset:16/little, Flags:32/little, _/binary>> =Segment,
    <<_:UpnOffset/binary, Upn:UpnLen/binary, _/binary>> = Segment,
    <<_:DnsNameOffset/binary, DnsName:DnsNameLen/binary, _/binary>> = Segment,
    #pac_upn_dns{
        upn = unicode:characters_to_binary(Upn, {utf16, little}, utf8),
        dns_name = unicode:characters_to_binary(DnsName, {utf16, little}, utf8)
    }.

decode_logon_info(Segment, Bin) ->
    S0 = rpce:start(Segment),
    {LogonTime, S1} = rpce:read(filetime, S0),
    {LogoffTime, S2} = rpce:read(filetime, S1),
    {KickOffTime, S3} = rpce:read(filetime, S2),
    {PasswordLastSet, S4} = rpce:read(filetime, S3),
    {PasswordCanChange, S5} = rpce:read(filetime, S4),
    {PasswordMustChange, S6} = rpce:read(filetime, S5),
    {EffNamePtr, S7} = rpce:read(rpc_unicode_string, S6),
    {FullNamePtr, S8} = rpce:read(rpc_unicode_string, S7),
    {LogonScriptPtr, S9} = rpce:read(rpc_unicode_string, S8),
    {ProfilePathPtr, S10} = rpce:read(rpc_unicode_string, S9),
    {HomeDirPtr, S11} = rpce:read(rpc_unicode_string, S10),
    {HomeDirDrivePtr, S12} = rpce:read(rpc_unicode_string, S11),
    {LogonCount, S13} = rpce:read(ushort, S12),
    {BadPasswordCount, S14} = rpce:read(ushort, S13),
    {UserId, S15} = rpce:read(ulong, S14),
    {PrimaryGroupId, S16} = rpce:read(ulong, S15),
    {GroupCount, S17} = rpce:read(ulong, S16),
    {GroupsPtr, S18} = rpce:read({pointer, {array, group_membership}}, S17),
    {UserFlags, S19} = rpce:read(ulong, S18),
    {_SessKey, S20} = rpce:read(user_session_key, S19),
    {LogonServerPtr, S21} = rpce:read(rpc_unicode_string, S20),
    {LogonDomainNamePtr, S22} = rpce:read(rpc_unicode_string, S21),
    {LogonDomainIdPtr, S23} = rpce:read({pointer, sid}, S22),
    {_Reserved1, S24} = rpce:read(ulong, S23),
    {_Reserved2, S25} = rpce:read(ulong, S24),
    {UAC, S26} = rpce:read(ulong, S25),
    {SubAuthStatus, S27} = rpce:read(ulong, S26),
    {LastSuccessfulILogon, S28} = rpce:read(filetime, S27),
    {LastFailedILogon, S29} = rpce:read(filetime, S28),
    {FailedILogonCount, S30} = rpce:read(ulong, S29),
    {_Reserved3, S31} = rpce:read(ulong, S30),
    {SidCount, S32} = rpce:read(ulong, S31),
    {SidPtr, S33} = rpce:read({pointer, {array, kerb_sid_and_attributes}}, S32),
    {RscGroupDomainSid, S34} = rpce:read({pointer, sid}, S33),
    {RscGroupCount, S35} = rpce:read(ulong, S34),
    {RscGroupPtr, S36} = rpce:read({pointer, {array, group_membership}}, S35),
    SFinal = rpce:finish(S36),

    Sids0 = rpce:get_ptr(SidPtr, SFinal),
    Sids1 = [S#sid_and_attributes{
        sid = rpce:get_ptr(SidPtr, SFinal)}
            || S = #sid_and_attributes{sid_ptr = SidPtr} <- Sids0],

    #pac_logon_info{
        times = #{
            logon => LogonTime,
            logoff => LogoffTime,
            kickoff => KickOffTime,
            pw_last_set => PasswordLastSet,
            pw_can_change => PasswordCanChange,
            pw_must_change => PasswordMustChange
        },
        ename = rpce:get_ptr(EffNamePtr, SFinal),
        fname = rpce:get_ptr(FullNamePtr, SFinal),
        logon_script = rpce:get_ptr(LogonScriptPtr, SFinal),
        profile_path = rpce:get_ptr(ProfilePathPtr, SFinal),
        homedir = rpce:get_ptr(HomeDirPtr, SFinal),
        home_drive = rpce:get_ptr(HomeDirDrivePtr, SFinal),
        logon_count = LogonCount,
        bad_pw_count = BadPasswordCount,
        userid = UserId,
        groups = rpce:get_ptr(GroupsPtr, SFinal),
        logon_server = rpce:get_ptr(LogonServerPtr, SFinal),
        domain = rpce:get_ptr(LogonDomainNamePtr, SFinal),
        domain_sid = rpce:get_ptr(LogonDomainIdPtr, SFinal),
        sids = Sids1
    }.
