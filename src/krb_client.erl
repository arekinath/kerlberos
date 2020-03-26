%% kerlberos
%%
%% Copyright 2015 Alex Wilson <alex@uq.edu.au>
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

%% @doc kerberos crypto module (based on rfc3961/3962).
-module(krb_client).
-behaviour(gen_fsm).

-include("KRB5.hrl").

-export([init/1, handle_info/3, terminate/3]).
-export([unauthed/2, unauthed/3, authed/2, authed/3, authed_send/2, authed_wait/2]).
-export([probe/2, probe_wait/2, auth/2, auth_wait/2]).

-export([open/1, open/2, close/1, authenticate/3, obtain_ticket/2]).

-opaque krb_client() :: pid().

-type kdc_spec() :: inet:ip_address() | inet:hostname() | {inet:ip_address() | inet:hostname(), Port :: integer()}.
-type open_option() :: {kdc, kdc_spec() | [kdc_spec()]} | {port, integer()}.
-type open_options() :: [open_option()].

-spec open(string()) -> {ok, krb_client()}.
open(Realm) -> open(Realm, #{}).

-spec open(string(), open_options()) -> {ok, krb_client()}.
open(Realm, Opts) when is_list(Realm) and is_map(Opts) ->
	gen_fsm:start_link(?MODULE, [Realm, Opts], []).

-spec authenticate(krb_client(), string() | [string()], string()) -> ok | {error, term()}.
authenticate(Client, Principal = [C | _], Secret) when is_list(C); is_binary(C) ->
	gen_fsm:sync_send_event(Client, {authenticate, Principal, Secret}, infinity);
authenticate(Client, Principal, Secret) ->
	authenticate(Client, [Principal], Secret).

-spec obtain_ticket(krb_client(), [string()]) -> {ok, Key :: #'EncryptionKey'{}, Ticket :: #'Ticket'{}} | {error, term()}.
obtain_ticket(Client, SvcPrincipal) ->
	gen_fsm:sync_send_event(Client, {obtain_ticket, SvcPrincipal}, infinity).

-spec close(krb_client()) -> ok.
close(Client) ->
	MRef = monitor(process, Client),
	Client ! shutdown,
	receive
		{'DOWN', MRef, _, _, _} -> ok
	end.

-record(state, {
	kdcs :: [{inet:ip_address() | inet:hostname(), Port :: integer()}],
	usock :: gen_udp:socket(),
	tsock :: gen_tcp:socket(),
	realm :: string(),
	tgtrealm :: string(),
	principal :: [binary()],
	secret :: binary(),
	auth_client :: term(),
	cipher_list :: [atom()],
	timeout :: integer(),
	etype :: atom(),
	salt :: binary(),
	key :: binary(),
	nonce :: integer(),
	expect :: [atom()],
	probe_timeouts = 0  :: integer(),
	timeouts = 0 :: integer(),
	cc :: pid(),
	svc_principal :: [binary()],
	svc_client :: term(),
	svc_key :: binary()
	}).

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
	transited,delegate,
	{skip,18}]).

send_kdc_pkt(Data, S = #state{tsock = undefined, usock = Sock, kdcs = [{Kdc, Port} | _]}) ->
	ok = gen_udp:send(Sock, Kdc, Port, Data);
send_kdc_pkt(Data, S = #state{tsock = Sock}) ->
	ok = gen_tcp:send(Sock, Data).

retry_connect(IP, Port, Opts, Timeout) ->
	retry_connect(IP, Port, Opts, Timeout div 3, 3).
retry_connect(IP, Port, Opts, Timeout, Retries) ->
	case gen_tcp:connect(IP, Port, Opts, Timeout) of
		R = {ok, _} -> R;
		{error, timeout} when Retries > 0 ->
			retry_connect(IP, Port, Opts, Timeout, Retries - 1);
		R = {error, _} -> R
	end.

lookup_kdcs(Domain) ->
    Results = inet_res:lookup("_kerberos._udp." ++ Domain, in, srv),
    [{Name, Port} || {_Prio, _Weight, Port, Name} <- Results].

init([Realm, Opts]) ->
	KdcPort = maps:get(port, Opts, 88),
	CipherList = maps:get(ciphers, Opts, [aes256_hmac_sha1, aes128_hmac_sha1, rc4_hmac, des_md5, des_md4, des_crc]),
	Timeout = maps:get(timeout, Opts, 1000),
	CC = case Opts of
		#{cc := CCPid} -> CCPid;
		#{cc_mod := CCMod} ->
			{ok, CCPid} = krbcc:start_link(CCMod, #{}),
			CCPid;
		_ ->
			{ok, CCPid} = krbcc:start_link(krbcc_ets, #{}),
			CCPid
	end,
	Kdcs = case Opts of
		#{kdc := L} when is_list(L) ->
			lists:map(fun
				({Host, Port}) -> {Host,Port};
				(Host) -> {Host, KdcPort}
			end, L);
		#{kdc := {Host, Port}} -> [{Host, Port}];
		#{kcd := Host} -> [{Host, KdcPort}];
		_ -> lookup_kdcs(string:to_lower(Realm))
	end,
	{ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
	{ok, unauthed, #state{realm = Realm, kdcs = Kdcs, usock = Sock, cipher_list = CipherList, timeout = Timeout, cc = CC}, 0}.

unauthed(timeout, S = #state{cc = CC, realm = Realm}) ->
	case krbcc:find_tickets(CC, #{service_principal => ["krbtgt", Realm]}) of
		{ok, Tgts = [_ | _]} ->
			LocalTgts = [T || T = #{realm := Realm} <- Tgts],
			Tgt = case LocalTgts of
				[T | _] -> T;
				_ -> [T | _] = Tgts, T
			end,
			#{realm := TgtRealm, key := KeyRec, user_principal := UserPrinc} = Tgt,
			#'EncryptionKey'{keytype = EType} = KeyRec,
			S1 = S#state{tgtrealm = TgtRealm, etype = EType, principal = UserPrinc},
			{next_state, authed, S1};
		_ ->
			{next_state, unauthed, S}
	end.

unauthed({authenticate, Principal, Secret}, From, S = #state{}) ->
	{next_state, probe, S#state{principal = Principal, secret = Secret, auth_client = From, probe_timeouts = 0}, 0};

unauthed({obtain_ticket, _}, From, S = #state{}) ->
	gen_fsm:reply(From, {error, not_authed}),
	{next_state, unauthed, S}.

probe(timeout, S = #state{kdcs = Kdcs, realm = Realm, principal = Principal, secret = Secret}) ->
	Options = sets:from_list([renewable,proxiable,forwardable]),
	ReqBody = #'KDC-REQ-BODY'{
		'kdc-options' = encode_bit_flags(Options, ?kdc_flags),
		cname = #'PrincipalName'{'name-type' = 1, 'name-string' = Principal},
		sname = #'PrincipalName'{'name-type' = 2, 'name-string' = ["krbtgt", Realm]},
		realm = Realm,
		%from = datetime_to_krbtime(Now),
		till = datetime_to_krbtime(calendar:system_time_to_universal_time(erlang:system_time(millisecond) + 4*3600*1000, millisecond)),
		nonce = crypto:rand_uniform(1, 1 bsl 30),
		etype = [krb_crypto:atom_to_etype(X) || X <- S#state.cipher_list]
	},
	Req = #'KDC-REQ'{
		pvno = 5,
		'msg-type' = 10,
		padata = [],
		'req-body' = ReqBody
	},
	{ok, Pkt} = 'KRB5':encode('AS-REQ', Req),
	ok = send_kdc_pkt(Pkt, S),
	{next_state, probe_wait, S#state{expect = ['KRB-ERROR']}, S#state.timeout}.

probe_wait(Err = #'KRB-ERROR'{'error-code' = 'KDC_ERR_ETYPE_NOSUPP'}, S = #state{auth_client = Client}) ->
	gen_fsm:reply(Client, {error, no_matching_ciphers}),
	{next_state, unauthed, S#state{expect = []}};

probe_wait(Err = #'KRB-ERROR'{'error-code' = 'KRB_ERR_RESPONSE_TOO_BIG'}, S = #state{kdcs = [{Kdc, Port} | _], timeout = T}) ->
	case retry_connect(Kdc, Port, [{active, true}, binary, {packet, 4}, {nodelay, true}], T) of
		{ok, Sock} ->
			ok = inet:setopts(S#state.usock, [{active, false}]),
			{next_state, probe, S#state{tsock = Sock}, 0};
		_ ->
			probe_wait(timeout, S)
	end;

probe_wait(Err = #'KRB-ERROR'{'error-code' = Code}, S = #state{auth_client = Client})
		when Code == 'KDC_ERR_C_PRINCIPAL_UNKNOWN'; Code == 'KDC_ERR_PRINCIPAL_NOT_UNIQUE'; Code == 'KDC_ERR_POLICY' ->
	gen_fsm:reply(Client, {error, bad_principal}),
	{next_state, unauthed, S#state{expect = []}};

probe_wait(Err = #'KRB-ERROR'{'error-code' = 'KDC_ERR_PREAUTH_REQUIRED'}, S = #state{}) ->
	PaDatas = Err#'KRB-ERROR'.'e-data',
	case [I || #'PA-DATA'{'padata-type' = 19, 'padata-value' = I} <- PaDatas] of
		[Etype2s] ->
			[#'ETYPE-INFO2-ENTRY'{etype = EType, salt = Salt} | _] = Etype2s,
			ETypeAtom = krb_crypto:etype_to_atom(EType),
			SaltBin = case ETypeAtom of rc4_hmac -> <<>>; _ -> list_to_binary(Salt) end,
			{next_state, auth, S#state{etype = ETypeAtom, salt = SaltBin}, 0};
		[] ->
			case [I || #'PA-DATA'{'padata-type' = 11, 'padata-value' = I} <- PaDatas] of
				[Etypes] ->
					[#'ETYPE-INFO-ENTRY'{etype = EType, salt = Salt} | _] = Etypes,
					ETypeAtom = krb_crypto:etype_to_atom(EType),
					{next_state, auth, S#state{etype = ETypeAtom, salt = Salt}, 0};
				[] ->
					case S#state.cipher_list of
						[Cipher | _] ->
							[User | _] = S#state.principal,
							{next_state, auth, S#state{etype = Cipher, salt = S#state.realm ++ User}, 0}
					end
			end
	end;

probe_wait(timeout, S = #state{kdcs = Kdcs, probe_timeouts = T, auth_client = Client}) when (T > length(Kdcs)) ->
	gen_fsm:reply(Client, {error, timeout}),
	{next_state, unauthed, S#state{expect = []}};
probe_wait(timeout, S = #state{kdcs = [This | Rest], probe_timeouts = T}) ->
	S2 = case S#state.tsock of
		undefined -> S;
		Sock ->
			gen_tcp:close(Sock),
			ok = inet:setopts(S#state.usock, [{active, true}]),
			S#state{tsock = undefined}
	end,
	{next_state, probe, S2#state{kdcs = Rest ++ [This], probe_timeouts = T + 1}, 0}.

auth(timeout, S = #state{kdcs = [Kdc | _], realm = Realm, principal = Principal, secret = Secret, etype = EType, salt = Salt}) ->
	NowUSec = erlang:system_time(microsecond),
	NowMSec = NowUSec div 1000,
	USec = NowUSec rem 1000,
	NowKrb = datetime_to_krbtime(calendar:system_time_to_universal_time(NowMSec, millisecond)),
	Options = sets:from_list([forwardable,proxiable,renewable]),
	Nonce = crypto:rand_uniform(1, 1 bsl 31),
	ReqBody = #'KDC-REQ-BODY'{
		'kdc-options' = encode_bit_flags(Options, ?kdc_flags),
		cname = #'PrincipalName'{'name-type' = 1, 'name-string' = Principal},
		sname = #'PrincipalName'{'name-type' = 2, 'name-string' = ["krbtgt", Realm]},
		realm = Realm,
		%from = NowKrb,
		till = datetime_to_krbtime(calendar:system_time_to_universal_time(NowMSec + 4*3600*1000, millisecond)),
		nonce = Nonce,
		etype = [krb_crypto:atom_to_etype(EType)]
	},
	PAEncTs = #'PA-ENC-TS-ENC'{
		patimestamp = NowKrb,
		pausec = USec
	},
	{ok, PAEncPlain} = 'KRB5':encode('PA-ENC-TS-ENC', PAEncTs),
	Key = krb_crypto:string_to_key(EType, iolist_to_binary(Secret), iolist_to_binary(Salt)),
	EncData = #'EncryptedData'{
		etype = krb_crypto:atom_to_etype(EType),
		cipher = krb_crypto:encrypt(EType, Key, PAEncPlain, #{usage => 1})
	},
	{ok, PAEnc} = 'KRB5':encode('PA-ENC-TIMESTAMP', EncData),
	PAData = [#'PA-DATA'{'padata-type' = 2, 'padata-value' = PAEnc}],
			  %#'PA-DATA'{'padata-type' = 3, 'padata-value' = Salt}],
	Req = #'KDC-REQ'{
		pvno = 5,
		'msg-type' = 10,
		padata = PAData,
		'req-body' = ReqBody
		},
	{ok, Pkt} = 'KRB5':encode('AS-REQ', Req),
	send_kdc_pkt(Pkt, S),
	{next_state, auth_wait, S#state{expect = ['AS-REP', 'KRB-ERROR'], key = Key, nonce = Nonce}, S#state.timeout}.

auth_wait({packet, <<>>}, S = #state{timeout = T}) ->
	{next_state, auth_wait, S, T};

auth_wait(R = #'KDC-REP'{'enc-part' = EncPart}, S = #state{auth_client = Client, nonce = Nonce}) ->
	NowKrb = datetime_to_krbtime(calendar:universal_time()),
	Valid = case EncPart of
		#'EncKDCRepPart'{nonce = Nonce, endtime = End, flags = Flags} ->
			if
				(End > NowKrb) ->
					case [lists:member(X, Flags) || X <- [pre_auth,initial]] of
						[true, true] -> true;
						_ -> false
					end;
				true -> false
			end;
		_ -> false
	end,
	case Valid of
		true ->
			#state{realm = Realm, cc = CC} = S,
			#'EncKDCRepPart'{key = KeyRec0} = EncPart,
			#'EncryptionKey'{keytype = KT0} = KeyRec0,
			EType = krb_crypto:etype_to_atom(KT0),
			KeyRec1 = KeyRec0#'EncryptionKey'{keytype = EType},
			#'KDC-REP'{ticket = Ticket} = R,
			#'Ticket'{realm = TgtRealm} = Ticket,
			ok = krbcc:store_ticket(CC, S#state.principal, KeyRec1, Ticket),
			gen_fsm:reply(Client, ok),
			{next_state, authed, S#state{expect = [], tgtrealm = TgtRealm}};
		false ->
			gen_fsm:reply(Client, {error, invalid_response}),
			{next_state, unauthed, S#state{expect = []}}
	end;

auth_wait(Err = #'KRB-ERROR'{'error-code' = 'KRB_ERR_RESPONSE_TOO_BIG'}, S = #state{kdcs = [{Kdc, Port} | _], timeout = T}) ->
	case retry_connect(Kdc, Port, [{active, true}, binary, {packet, 4}, {nodelay, true}], T) of
		{ok, Sock} ->
			ok = inet:setopts(S#state.usock, [{active, false}]),
			{next_state, auth, S#state{tsock = Sock}, 0};
		_ ->
			auth_wait(timeout, S)
	end;

auth_wait(Err = #'KRB-ERROR'{'error-code' = Code}, S = #state{auth_client = Client})
		when Code == 'KDC_ERR_PREAUTH_FAILED'; Code == 'KRB_AP_ERR_BAD_INTEGRITY' ->
	gen_fsm:reply(Client, {error, bad_secret}),
	{next_state, unauthed, S#state{expect = []}};

auth_wait(Err = #'KRB-ERROR'{}, S = #state{auth_client = Client}) ->
	gen_fsm:reply(Client, {error, {krb5_error, Err#'KRB-ERROR'.'error-code', Err#'KRB-ERROR'.'e-text'}}),
	{next_state, unauthed, S#state{expect = []}};

auth_wait(timeout, S = #state{kdcs = Kdcs, timeouts = T, auth_client = Client}) when (T > length(Kdcs)) ->
	gen_fsm:reply(Client, {error, timeout}),
	S2 = case S#state.tsock of
		undefined -> S;
		Sock ->
			gen_tcp:close(Sock),
			ok = inet:setopts(S#state.usock, [{active, true}]),
			S#state{tsock = undefined}
	end,
	{next_state, unauthed, S2#state{expect = []}};
auth_wait(timeout, S = #state{kdcs = [This | Rest], timeouts = T}) ->
	S2 = case S#state.tsock of
		undefined -> S;
		Sock ->
			gen_tcp:close(Sock),
			ok = inet:setopts(S#state.usock, [{active, true}]),
			S#state{tsock = undefined}
	end,
	{next_state, auth, S2#state{kdcs = Rest ++ [This], timeouts = T + 1}, 0}.

authed(timeout, S = #state{}) ->
	% check in cc for existing tgt
	{next_state, authed, S}.

authed({obtain_ticket, SvcPrincipal}, From, S = #state{}) ->
	S1 = S#state{svc_principal = SvcPrincipal, svc_client = From},
	{next_state, authed_send, S1, 0}.

authed_send(timeout, S = #state{realm = Realm, tgtrealm = TgtRealm, principal = UserPrincipal, svc_principal = SvcPrincipal, cc = CC}) ->
	NowUSec = erlang:system_time(microsecond),
	NowMSec = NowUSec div 1000,
	USec = NowUSec rem 1000,
	NowKrb = datetime_to_krbtime(calendar:system_time_to_universal_time(NowMSec, millisecond)),
	{ok, KeyRec, Ticket} = krbcc:get_ticket(CC, UserPrincipal, ["krbtgt", Realm], TgtRealm),
	#'EncryptionKey'{keytype = EType, keyvalue = Key} = KeyRec,
	SvcKey = crypto:strong_rand_bytes(byte_size(Key)),
	SvcEncKey = #'EncryptionKey'{
		keytype = krb_crypto:atom_to_etype(EType),
		keyvalue = SvcKey
	},
	Options = sets:from_list([renewable, forwardable, canonicalize]),
	Nonce = crypto:rand_uniform(1, 1 bsl 30),
	ReqBody = #'KDC-REQ-BODY'{
		'kdc-options' = encode_bit_flags(Options, ?kdc_flags),
		sname = #'PrincipalName'{'name-type' = 2, 'name-string' = SvcPrincipal},
		realm = Realm,
		till = datetime_to_krbtime(calendar:system_time_to_universal_time(NowMSec + 4*3600*1000, millisecond)),
		nonce = Nonce,
		etype = [krb_crypto:atom_to_etype(X) || X <- S#state.cipher_list]
	},
	{ok, ReqBodyBin} = 'KRB5':encode('KDC-REQ-BODY', ReqBody),
	CType = krb_crypto:ctype_for_etype(EType),
	Cksum = #'Checksum'{
		cksumtype = krb_crypto:atom_to_ctype(CType),
		checksum = krb_crypto:checksum(CType, Key, ReqBodyBin, #{usage => 6})
	},
	Auth = #'Authenticator'{
		'authenticator-vno' = 5,
		crealm = TgtRealm,
		cname = #'PrincipalName'{'name-type' = 1, 'name-string' = UserPrincipal},
		ctime = NowKrb,
		cusec = USec,
		cksum = Cksum,
		subkey = SvcEncKey
	},
	{ok, AuthPlain} = 'KRB5':encode('Authenticator', Auth),
	EncData = #'EncryptedData'{
		etype = krb_crypto:atom_to_etype(EType),
		cipher = krb_crypto:encrypt(EType, Key, AuthPlain, #{usage => 7})
	},
	APReq = #'AP-REQ'{
		pvno = 5,
		'msg-type' = 14,
		ticket = Ticket,
		authenticator = EncData,
		'ap-options' = <<0:32>>
	},
	{ok, APReqBin} = 'KRB5':encode('AP-REQ', APReq),
	{ok, PacReqBin} = 'KRB5':encode('PA-PAC-REQUEST',
		#'PA-PAC-REQUEST'{'include-pac' = true}),
	PAData = [
		#'PA-DATA'{'padata-type' = 1, 'padata-value' = APReqBin},
		#'PA-DATA'{'padata-type' = 128, 'padata-value' = PacReqBin}
	],
	Req = #'KDC-REQ'{
		pvno = 5,
		'msg-type' = 12,
		padata = PAData,
		'req-body' = ReqBody
	},
	{ok, Pkt} = 'KRB5':encode('TGS-REQ', Req),
	send_kdc_pkt(Pkt, S),
	{next_state, authed_wait, S#state{expect = ['TGS-REP', 'KRB-ERROR'], nonce = Nonce, svc_key = SvcKey, timeouts = 0}, S#state.timeout}.

authed_wait(R = #'KDC-REP'{'enc-part' = EncPart}, S = #state{svc_principal = SvcPrinc, svc_client = Client, nonce = Nonce}) ->
	NowKrb = datetime_to_krbtime(calendar:universal_time()),
	Valid = case EncPart of
		#'EncKDCRepPart'{nonce = Nonce, endtime = End, flags = Flags} ->
			if
				(End > NowKrb) -> true;
				true -> false
			end;
		_ -> false
	end,
	case Valid of
		true ->
			#state{realm = Realm, cc = CC} = S,
			#'EncKDCRepPart'{key = KeyRec0} = EncPart,
			#'EncryptionKey'{keytype = KT0} = KeyRec0,
			EType = krb_crypto:etype_to_atom(KT0),
			KeyRec1 = KeyRec0#'EncryptionKey'{keytype = EType},
			#'KDC-REP'{ticket = Ticket} = R,
			ok = krbcc:store_ticket(CC, S#state.principal, KeyRec1, Ticket),
			gen_fsm:reply(Client, {ok, KeyRec1, Ticket}),
			{next_state, authed, S#state{expect = []}};
		false ->
			gen_fsm:reply(Client, {error, invalid_response}),
			{next_state, authed, S#state{expect = []}}
	end;

authed_wait(Err = #'KRB-ERROR'{'error-code' = 'KRB_ERR_RESPONSE_TOO_BIG'}, S = #state{kdcs = [{Kdc, Port} | _], timeout = T}) ->
	case retry_connect(Kdc, Port, [{active, true}, binary, {packet, 4}, {nodelay, true}], T) of
		{ok, Sock} ->
			ok = inet:setopts(S#state.usock, [{active, false}]),
			{next_state, authed_send, S#state{tsock = Sock}, 0};
		_ ->
			authed_wait(timeout, S)
	end;

authed_wait(Err = #'KRB-ERROR'{'error-code' = Code}, S = #state{svc_client = Client})
		when Code == 'KDC_ERR_PREAUTH_FAILED'; Code == 'KRB_AP_ERR_BAD_INTEGRITY' ->
	gen_fsm:reply(Client, {error, bad_secret}),
	{next_state, authed, S#state{expect = []}};

authed_wait(Err = #'KRB-ERROR'{}, S = #state{svc_client = Client}) ->
	gen_fsm:reply(Client, {error, {krb5_error, Err#'KRB-ERROR'.'error-code', Err#'KRB-ERROR'.'e-text'}}),
	io:format("~p\n", [Err]),
	{next_state, authed, S#state{expect = []}};

authed_wait(timeout, S = #state{kdcs = Kdcs, timeouts = T, auth_client = Client}) when (T > length(Kdcs)) ->
	gen_fsm:reply(Client, {error, timeout}),
	S2 = case S#state.tsock of
		undefined -> S;
		Sock ->
			gen_tcp:close(Sock),
			ok = inet:setopts(S#state.usock, [{active, true}]),
			S#state{tsock = undefined}
	end,
	{next_state, authed, S2#state{expect = []}};
authed_wait(timeout, S = #state{kdcs = [This | Rest], timeouts = T}) ->
	S2 = case S#state.tsock of
		undefined -> S;
		Sock ->
			gen_tcp:close(Sock),
			ok = inet:setopts(S#state.usock, [{active, true}]),
			S#state{tsock = undefined}
	end,
	{next_state, authed_send, S2#state{kdcs = Rest ++ [This], timeouts = T + 1}, 0}.

handle_info(shutdown, _State, S = #state{}) ->
	{stop, normal, S};
handle_info({tcp_closed, Sock}, State, S = #state{tsock = Sock}) ->
	?MODULE:State(timeout, S);
handle_info({tcp, Sock, Data}, State, S = #state{tsock = Sock, expect = Decoders}) ->
	try_decode(Data, State, S, Decoders);
handle_info({udp, Sock, IP, Port, Data}, State, S = #state{expect = Decoders}) ->
	try_decode(IP, Port, Data, State, S, Decoders).

terminate(Reason, State, S = #state{tsock = Sock}) when Sock =/= undefined ->
	gen_tcp:close(Sock),
	terminate(Reason, State, S#state{tsock = undefined});
terminate(Reason, State, S = #state{usock = Sock}) when Sock =/= undefined ->
	gen_udp:close(Sock),
	terminate(Reason, State, S#state{usock = undefined});
terminate(Reason, State, S = #state{}) ->
	ok.

try_decode(IP, Port, Data, State, S, Decoders) ->
	try_decode({packet, IP, Port, Data}, Data, State, S, Decoders).
try_decode(Data, State, S, Decoders) ->
	try_decode({packet, Data}, Data, State, S, Decoders).

try_decode(FallbackMsg, Data, State, S, _) when byte_size(Data) == 0 ->
	?MODULE:State(FallbackMsg, S);
try_decode(FallbackMsg, Data, State, S, []) ->
	?MODULE:State(FallbackMsg, S);
try_decode(FallbackMsg, Data, State, S, [NextDecoder | Rest]) ->
	case 'KRB5':decode(NextDecoder, Data) of
		{ok, Record, Leftover} ->
			case Leftover of
				<<>> -> ok;
				_ -> ok %io:format("warning: leftover on ~p: ~p\n", [NextDecoder, Leftover])
			end,
			{Record2, S2} = post_decode(State, Record, S),
			?MODULE:State(Record2, S2);
		_ ->
			try_decode(FallbackMsg, Data, State, S, Rest)
	end.

post_decode(_State, Pa = #'PA-DATA'{'padata-type' = 11, 'padata-value' = Bin}, S) when is_binary(Bin) ->
	case 'KRB5':decode('ETYPE-INFO', Bin) of
		{ok, EtypeInfo, <<>>} ->
			{Pa#'PA-DATA'{'padata-value' = EtypeInfo}, S};
		_ -> {Pa, S}
	end;
post_decode(_State, Pa = #'PA-DATA'{'padata-type' = 19, 'padata-value' = Bin}, S) when is_binary(Bin) ->
	case 'KRB5':decode('ETYPE-INFO2', Bin) of
		{ok, EtypeInfo, <<>>} ->
			{Pa#'PA-DATA'{'padata-value' = EtypeInfo}, S};
		_ -> {Pa, S}
	end;
post_decode(State, E = #'KRB-ERROR'{'error-code' = I}, S) when is_integer(I) ->
	IC = krb_errors:err_to_atom(I),
	post_decode(State, E#'KRB-ERROR'{'error-code' = IC}, S);
post_decode(State, E = #'KRB-ERROR'{'e-data' = EData}, S) when is_binary(EData) ->
	case 'KRB5':decode('METHOD-DATA', EData) of
		{ok, PaDatas, <<>>} ->
			{PaDatas2, S2} = lists:mapfoldl(fun (Pa, SS) ->
				post_decode(State, Pa, SS)
			end, S, PaDatas),
			{E#'KRB-ERROR'{'e-data' = PaDatas2}, S2};
		_ -> {E, S}
	end;
post_decode(auth_wait, R = #'KDC-REP'{'enc-part' = #'EncryptedData'{etype = ETypeId, kvno = KvNo, cipher = EP}}, S = #state{etype = EType, key = Key}) when is_binary(EP) ->
	Etype = krb_crypto:etype_to_atom(ETypeId),
	case (catch krb_crypto:decrypt(EType, Key, EP, #{usage => 3})) of
		{'EXIT', _Why} -> {R, S};
		Plain -> inner_decode_tgs_or_as(auth_wait, Plain, R, S)
	end;
post_decode(authed_wait, R = #'KDC-REP'{'enc-part' = #'EncryptedData'{etype = ETypeId, kvno = KvNo, cipher = EP}}, S = #state{etype = EType, svc_key = Key}) when is_binary(EP) ->
	Etype = krb_crypto:etype_to_atom(ETypeId),
	case (catch krb_crypto:decrypt(EType, Key, EP, #{usage => 9})) of
		{'EXIT', _Why} -> {R, S};
		Plain -> inner_decode_tgs_or_as(authed_wait, Plain, R, S)
	end;
post_decode(_State, R = #'EncKDCRepPart'{flags = Flags}, S) ->
	FlagSet = decode_bit_flags(Flags, ?ticket_flags),
	{R#'EncKDCRepPart'{flags = sets:to_list(FlagSet)}, S};
post_decode(_State, Rec, S) -> {Rec, S}.

inner_decode_tgs_or_as(State, Plain, R, S = #state{}) ->
	case 'KRB5':decode('EncTGSRepPart', Plain) of
		{ok, EncPart, _} ->
			{EncPart2, S2} = post_decode(State, EncPart, S),
			{R#'KDC-REP'{'enc-part' = EncPart2}, S2};
		_ ->
			inner_decode_as(State, Plain, R, S)
	end.

inner_decode_as(State, Plain, R, S = #state{}) ->
	case 'KRB5':decode('EncASRepPart', Plain) of
		{ok, EncPart, _} ->
			{EncPart2, S2} = post_decode(State, EncPart, S),
			{R#'KDC-REP'{'enc-part' = EncPart2}, S2};
		_ ->
			% HACK ALERT
			% microsoft's older krb5 implementations often chop off the front of the EncASRepPart
			% what you get is just its innards starting with an un-tagged EncryptionKey
			case 'KRB5':decode('EncryptionKey', Plain) of
				{ok, K, B} when byte_size(B) > 0 ->
					% reconstruct the front part that's missing -- first, the context #0 tag for EncryptionKey
					{LenBytes, _} = asn1_encode_length(byte_size(Plain) - byte_size(B)),
					All = <<1:1, 0:1, 1:1, 0:5, (list_to_binary(LenBytes))/binary, Plain/binary>>,
					% then the sequence tag to go on the very front
					{LenBytes2, _} = asn1_encode_length(byte_size(All)),
					Plain2 = <<0:1, 0:1, 1:1, 16:5, (list_to_binary(LenBytes2))/binary, All/binary>>,

					% don't bother reconstructing the application tag for EncASRepPart, just decode it here
					% as a plain EncKDCRepPart
					case 'KRB5':decode('EncKDCRepPart', Plain2) of
						{ok, EncPart, _} ->
							% yay we win
							{EncPart2, S2} = post_decode(State, EncPart, S),
							{R#'KDC-REP'{'enc-part' = EncPart2}, S2};
						_ -> {R, S}
					end;
				_ ->
					{R, S}
			end
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

datetime_to_krbtime({{Y, M, D}, {Hr, Min, Sec}}) ->
	lists:flatten(io_lib:format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
		[Y, M, D, Hr, Min, Sec])).

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
