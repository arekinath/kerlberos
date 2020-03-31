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

-record(sid, {
	revision :: integer(),
	identifier_auth :: integer(),
	sub_auths :: [integer()]}).
-record(sid_and_attributes, {
	sid_ptr :: rpce:rpce_ptr(),
	sid = deferred :: #sid{} | deferred,
	attrs :: integer()}).
-record(group_membership, {
	rid :: integer(),
	attrs :: integer()}).

-record(pac, {version :: integer(), buffers :: [pac_buffer()]}).
-record(pac_unknown, {type :: integer(), data :: binary()}).
-record(pac_client_info, {tgt_time :: integer(), name :: binary()}).
-record(pac_upn_dns, {upn :: binary(), dns_name :: binary()}).
-record(pac_logon_info, {
	times = #{} :: #{atom() => integer() | never | null},
	ename :: binary(),
	fname :: binary(),
	logon_script :: binary(),
	profile_path :: binary(),
	homedir :: binary(),
	home_drive :: binary(),
	logon_count :: integer(),
	bad_pw_count :: integer(),
	userid :: integer(),
	groups :: [#group_membership{}],
	logon_server :: binary(),
	domain :: binary(),
	domain_sid :: #sid{},
	sids = [#sid{}]
	}).
-type pac_buffer() :: #pac_unknown{} | #pac_client_info{} | #pac_upn_dns{}.
