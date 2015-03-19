%% kerlberos
%%
%% Copyright (c) 2015, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc kerberos crypto module (based on rfc3961/3962).
-module(krb_client).
-behaviour(gen_fsm).

-include("KRB5.hrl").

-export([init/1, handle_info/3, terminate/3]).
-export([unauthed/2, unauthed/3]).
-export([probe/2, probe_wait/2, auth/2, auth_wait/2]).

-export([open/1, open/2, authenticate/3]).

-opaque krb_client() :: pid().

-type kdc_spec() :: inet:ip_address() | inet:hostname() | {inet:ip_address() | inet:hostname(), Port :: integer()}.
-type open_option() :: {kdc, kdc_spec() | [kdc_spec()]} | {port, integer()}.
-type open_options() :: [open_option()].

-spec open(string()) -> {ok, krb_client()}.
open(Realm) -> open(Realm, []).

-spec open(string(), open_options()) -> {ok, krb_client()}.
open(Realm, Opts) when is_list(Realm) and is_list(Opts) ->
	gen_fsm:start_link(?MODULE, [Realm, Opts], []).

-spec authenticate(krb_client(), string() | [string()], string()) -> ok | {error, term()}.
authenticate(Client, Principal = [C | _], Secret) when is_list(C); is_binary(C) ->
	gen_fsm:sync_send_event(Client, {authenticate, Principal, Secret});
authenticate(Client, Principal, Secret) ->
	authenticate(Client, [Principal], Secret).

-record(state, {
	kdcs :: [{inet:ip_address() | inet:hostname(), Port :: integer()}],
	sock :: gen_udp:socket(),
	realm :: string(),
	principal :: [binary()],
	secret :: binary(),
	auth_client :: term(),
	cipher_list :: [atom()],
	timeout :: integer(),
	etype :: atom(),
	salt :: binary(),
	key :: binary(),
	nonce :: integer(),
	expect :: [atom()]
	}).

-define(kdc_flags, [validate, renew, skip, enc_tkt_in_skey, renewable_ok, disable_transited, {skip, 14}, hw_auth, skip, pk_cross, renewable, skip, postdated, allow_postdate, proxy, proxiable, forwarded, forwardable, skip]).

-define(ticket_flags, [{skip, 18}, delegate, transited, hw_auth, pre_auth, initial, renewable, invalid, postdated, allow_postdate, proxy, proxiable, forwarded, forwardable, skip]).

lookup_kdcs(Domain) ->
    Results = inet_res:lookup("_kerberos._udp." ++ Domain, in, srv),
    [{Name, Port} || {_Prio, _Weight, Port, Name} <- Results].

init([Realm, Opts]) ->
	KdcPort = proplists:get_value(port, Opts, 88),
	CipherList = proplists:get_value(ciphers, Opts, [aes256_hmac_sha1, aes128_hmac_sha1, des_md5, des_md4, des_crc]),
	Timeout = proplists:get_value(timeout, Opts, 1000),
	Kdcs = case proplists:get_value(kdc, Opts) of
		undefined -> lookup_kdcs(string:to_lower(Realm));
		L when is_list(L) ->
			lists:map(fun
				({Host, Port}) -> {Host,Port};
				(Host) -> {Host, KdcPort}
			end, L);
		{Host, Port} -> [{Host, Port}];
		Host -> [{Host, KdcPort}]
	end,
	{ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
	{ok, unauthed, #state{realm = Realm, kdcs = Kdcs, sock = Sock, cipher_list = CipherList, timeout = Timeout}, 0}.

unauthed(timeout, S = #state{}) ->
	% check in cc for existing tgt
	{next_state, unauthed, S}.

unauthed({authenticate, Principal, Secret}, From, S = #state{}) ->
	{next_state, probe, S#state{principal = Principal, secret = Secret, auth_client = From}, 0}.

probe(timeout, S = #state{sock = Sock, kdcs = Kdcs, realm = Realm, principal = Principal, secret = Secret}) ->
	Now = os:timestamp(),
	Options = sets:from_list([renewable]),
	<<Flags:32/big>> = encode_bit_flags(Options, ?kdc_flags),
	ReqBody = #'KDC-REQ-BODY'{
		'kdc-options' = <<Flags:32/little>>,
		cname = #'PrincipalName'{'name-type' = 1, 'name-string' = Principal},
		sname = #'PrincipalName'{'name-type' = 2, 'name-string' = ["krbtgt", Realm]},
		realm = Realm,
		%from = datetime_to_krbtime(Now),
		till = datetime_to_krbtime(calendar:now_to_universal_time(now_add(Now, 4*3600*1000))),
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
	[{Kdc, Port} | _] = Kdcs,
	io:format("sending probe to ~p:~p\n", [Kdc, Port]),
	ok = gen_udp:send(Sock, Kdc, Port, Pkt),
	{next_state, probe_wait, S#state{expect = ['KRB-ERROR']}, S#state.timeout}.

probe_wait(Err = #'KRB-ERROR'{'error-code' = 14}, S = #state{auth_client = Client}) ->
	gen_fsm:reply(Client, {error, no_matching_ciphers}),
	{next_state, unauthed, S#state{expect = []}};

probe_wait(Err = #'KRB-ERROR'{'error-code' = Code}, S = #state{auth_client = Client}) 
		when Code == 6; Code == 8; Code == 12 ->
	gen_fsm:reply(Client, {error, bad_principal}),
	{next_state, unauthed, S#state{expect = []}};

probe_wait(Err = #'KRB-ERROR'{'error-code' = 25}, S = #state{}) ->
	io:format("got need-preauth reply\n"),
	PaDatas = Err#'KRB-ERROR'.'e-data',
	case [I || #'PA-DATA'{'padata-type' = 19, 'padata-value' = I} <- PaDatas] of
		[Etype2s] ->
			[#'ETYPE-INFO2-ENTRY'{etype = EType, salt = Salt} | _] = Etype2s,
			ETypeAtom = krb_crypto:etype_to_atom(EType),
			io:format("preferred cipher = ~p\n", [ETypeAtom]),
			{next_state, auth, S#state{etype = ETypeAtom, salt = list_to_binary(Salt)}, 0};
		[] ->
			case [I || #'PA-DATA'{'padata-type' = 11, 'padata-value' = I} <- PaDatas] of
				[Etypes] ->
					[#'ETYPE-INFO-ENTRY'{etype = EType, salt = Salt} | _] = Etypes,
					ETypeAtom = krb_crypto:etype_to_atom(EType),
					io:format("preferred cipher = ~p\n", [ETypeAtom]),
					{next_state, auth, S#state{etype = ETypeAtom, salt = Salt}, 0};
				[] ->
					case S#state.cipher_list of
						[Cipher] ->
							io:format("server returned no ETYPE-INFO, but we only have one cipher, so we'll try ~p\n", [Cipher]),
							[User | _] = S#state.principal,
							{next_state, auth, S#state{etype = Cipher, salt = S#state.realm ++ User}, 0};
						_ ->
							probe_wait(timeout, S)
					end
			end
	end;

probe_wait(timeout, S = #state{kdcs = [This | Rest]}) ->
	{next_state, probe, S#state{kdcs = Rest ++ [This]}, 0}.

auth(timeout, S = #state{sock = Sock, kdcs = [Kdc | _], realm = Realm, principal = Principal, secret = Secret, etype = EType, salt = Salt}) ->
	Now = {_, _, USec} = os:timestamp(),
	NowKrb = datetime_to_krbtime(calendar:now_to_universal_time(Now)),
	Options = sets:from_list([renewable]),
	Nonce = crypto:rand_uniform(1, 1 bsl 31),
	<<Flags:32/big>> = encode_bit_flags(Options, ?kdc_flags),
	ReqBody = #'KDC-REQ-BODY'{
		'kdc-options' = <<Flags:32/little>>,
		cname = #'PrincipalName'{'name-type' = 1, 'name-string' = Principal},
		sname = #'PrincipalName'{'name-type' = 2, 'name-string' = ["krbtgt", Realm]},
		realm = Realm,
		%from = NowKrb,
		till = datetime_to_krbtime(calendar:now_to_universal_time(now_add(Now, 4*3600*1000))),
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
		cipher = krb_crypto:encrypt(EType, Key, PAEncPlain, [{usage, 1}])
	},
	{ok, PAEnc} = 'KRB5':encode('PA-ENC-TIMESTAMP', EncData),
	PAData = [#'PA-DATA'{'padata-type' = 2, 'padata-value' = PAEnc},
			  #'PA-DATA'{'padata-type' = 3, 'padata-value' = Salt}],
	Req = #'KDC-REQ'{
		pvno = 5,
		'msg-type' = 10,
		padata = PAData,
		'req-body' = ReqBody
		},
	{ok, Pkt} = 'KRB5':encode('AS-REQ', Req),
	{Host, Port} = Kdc,
	io:format("sending auth request to ~p:~p\n", [Host, Port]),
	ok = gen_udp:send(Sock, Host, Port, Pkt),
	{next_state, auth_wait, S#state{expect = ['AS-REP', 'KRB-ERROR'], key = Key, nonce = Nonce}, S#state.timeout}.

auth_wait(R = #'KDC-REP'{'enc-part' = EncPart}, S = #state{auth_client = Client, nonce = Nonce}) ->
	Now = os:timestamp(),
	NowKrb = datetime_to_krbtime(calendar:now_to_universal_time(Now)),
	Valid = case EncPart of
		#'EncKDCRepPart'{nonce = Nonce, endtime = End} ->
			if
				(End > NowKrb) -> true;
				true -> false
			end;
		_ -> false
	end,
	case Valid of
		true ->
			gen_fsm:reply(Client, ok),
			% change me
			{next_state, unauthed, S#state{expect = []}};
		false ->
			gen_fsm:reply(Client, {error, invalid_response}),
			{next_state, unauthed, S#state{expect = []}}
	end;

auth_wait(Err = #'KRB-ERROR'{'error-code' = Code}, S = #state{auth_client = Client}) 
		when Code == 24; Code == 31 ->
	gen_fsm:reply(Client, {error, bad_secret}),
	{next_state, unauthed, S#state{expect = []}};

auth_wait(Err = #'KRB-ERROR'{}, S = #state{auth_client = Client}) ->
	gen_fsm:reply(Client, {error, {krb5_error, Err#'KRB-ERROR'.'error-code', Err#'KRB-ERROR'.'e-text'}}),
	{next_state, unauthed, S#state{expect = []}};

auth_wait(timeout, S = #state{auth_client = Client}) ->
	gen_fsm:reply(Client, {error, timeout}),
	{next_state, unauthed, S#state{expect = []}}.

handle_info({udp, Sock, IP, Port, Data}, State, S = #state{sock = Sock, expect = Decoders}) ->
	try_decode(IP, Port, Data, State, S, Decoders).

terminate(Reason, State, #state{sock = Sock}) ->
	io:format("client terminating in state ~p: ~p\n", [State, Reason]),
	gen_udp:close(Sock).

try_decode(IP, Port, Data, State, S, []) ->
	?MODULE:State({packet, IP, Port, Data}, S);
try_decode(IP, Port, Data, State, S, [NextDecoder | Rest]) ->
	case 'KRB5':decode(NextDecoder, Data) of
		{ok, Record, Leftover} ->
			case Leftover of
				<<>> -> ok;
				_ -> io:format("warning: leftover on ~p: ~p\n", [NextDecoder, Leftover])
			end,
			{Record2, S2} = post_decode(Record, S),
			?MODULE:State(Record2, S2);
		_ ->
			try_decode(IP, Port, Data, State, S, Rest)
	end.

post_decode(Pa = #'PA-DATA'{'padata-type' = 11, 'padata-value' = Bin}, S) when is_binary(Bin) ->
	case 'KRB5':decode('ETYPE-INFO', Bin) of
		{ok, EtypeInfo, <<>>} ->
			{Pa#'PA-DATA'{'padata-value' = EtypeInfo}, S};
		_ -> {Pa, S}
	end;
post_decode(Pa = #'PA-DATA'{'padata-type' = 19, 'padata-value' = Bin}, S) when is_binary(Bin) ->
	case 'KRB5':decode('ETYPE-INFO2', Bin) of
		{ok, EtypeInfo, <<>>} ->
			{Pa#'PA-DATA'{'padata-value' = EtypeInfo}, S};
		_ -> {Pa, S}
	end;
post_decode(E = #'KRB-ERROR'{'e-data' = EData}, S) when is_binary(EData) ->
	case 'KRB5':decode('METHOD-DATA', EData) of
		{ok, PaDatas, <<>>} ->
			{PaDatas2, S2} = lists:mapfoldl(fun post_decode/2, S, PaDatas),
			{E#'KRB-ERROR'{'e-data' = PaDatas2}, S2};
		_ -> {E, S}
	end;
post_decode(R = #'KDC-REP'{'enc-part' = #'EncryptedData'{cipher = EP}}, S = #state{etype = EType, key = Key}) when is_binary(EP) ->
	case (catch krb_crypto:decrypt(EType, Key, EP, [{usage, 3}])) of
		{'EXIT', _} -> {R, S};
		Plain ->
			case 'KRB5':decode('EncTGSRepPart', Plain) of
				{ok, EncPart, _} ->
					{EncPart2, S2} = post_decode(EncPart, S),
					{R#'KDC-REP'{'enc-part' = EncPart2}, S2};
				_ -> {R, S}
			end
	end;
post_decode(R = #'EncKDCRepPart'{flags = <<Flags:32/little>>}, S) ->
	FlagSet = decode_bit_flags(<<Flags:32/big>>, ?ticket_flags),
	{R#'EncKDCRepPart'{flags = sets:to_list(FlagSet)}, S};
post_decode(Rec, S) -> {Rec, S}.

datetime_to_krbtime({{Y, M, D}, {Hr, Min, Sec}}) ->
	lists:flatten(io_lib:format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
		[Y, M, D, Hr, Min, Sec])).

now_add({MS, S, US}, Add) ->
	now_normalise({MS, S, US + Add * 1000}).

now_normalise({MS, S, US}) when US >= 1000000 ->
	now_normalise({MS, S + (US div 1000000), US rem 1000000});
now_normalise({MS, S, US}) when S >= 1000000 ->
	now_normalise({MS + (S div 1000000), S rem 1000000, US});
now_normalise({MS, S, US}) when US < 0 ->
	STake = lists:max([1, (abs(US) div 100000)]),
	now_normalise({MS, S - STake, US + STake * 1000000});
now_normalise({MS, S, US}) when S < 0 ->
	STake = lists:max([1, (abs(S) div 100000)]),
	now_normalise({MS - STake, S + STake * 1000000, US});
now_normalise(Ts) -> Ts.

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
