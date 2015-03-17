#!/usr/bin/env escript
%%! -smp disable -pa ebin -env ERL_LIBS deps

-mode(compile).

-include("include/KRB5.hrl").

-define(kdc_flags, [validate, renew, skip, enc_tkt_in_skey, renewable_ok, disable_transited, {skip, 14}, hw_auth, skip, pk_cross, renewable, skip, postdated, allow_postdate, proxy, proxiable, forwarded, forwardable, skip]).

main([]) ->
	Now = {_, _, USec} = os:timestamp(),
	NowKrb = datetime_to_krbtime(calendar:now_to_universal_time(Now)),
	Options = sets:from_list([renewable]),
	Cipher = des_crc,
	ReqBody = #'KDC-REQ-BODY'{
		'kdc-options' = encode_bit_flags(Options, ?kdc_flags),
		cname = #'PrincipalName'{'name-type' = 1, 'name-string' = ["s7654321"]},
		sname = #'PrincipalName'{'name-type' = 2, 'name-string' = ["krbtgt", "KRB5.UQ.EDU.AU"]},
		realm = "KRB5.UQ.EDU.AU",
		%from = NowKrb,
		till = datetime_to_krbtime(calendar:now_to_universal_time(now_add(Now, 4*3600*1000))),
		nonce = crypto:rand_uniform(1, 1 bsl 30),
		etype = [rfc3961:atom_to_etype(X) || X <- [des_crc, des_md4, des_md5, aes256_hmac_sha1, aes128_hmac_sha1]]
	},
	PAEncTs = #'PA-ENC-TS-ENC'{
		patimestamp = NowKrb,
		pausec = USec
	},
	{ok, PAEncPlain} = 'KRB5':encode('PA-ENC-TS-ENC', PAEncTs),
	io:format("enc-ts = ~s\n", ['KRB5':pretty_print(PAEncTs)]),

	Salt = <<"KRB5.UQ.EDU.AUs7654321">>,
	Key = rfc3961:string_to_key(Cipher, <<"Itig1234">>, Salt),
	io:format("using key ~p\n", [Key]),
	EncData = #'EncryptedData'{
		etype = rfc3961:atom_to_etype(Cipher),
		kvno = 1,
		cipher = rfc3961:encrypt(Cipher, Key, PAEncPlain)
	},
	io:format("encdata = ~s\n", ['KRB5':pretty_print(EncData)]),
	{ok, PAEnc} = 'KRB5':encode('PA-ENC-TIMESTAMP', EncData),
	PAData = [],%[#'PA-DATA'{'padata-type' = 2, 'padata-value' = PAEnc},
			 % #'PA-DATA'{'padata-type' = 3, 'padata-value' = Salt}],
	Req = #'KDC-REQ'{
		pvno = 5,
		'msg-type' = 10,
		padata = PAData,
		'req-body' = ReqBody
		},
	io:format("~s\n", ['KRB5':pretty_print(Req)]),
	{ok, Pkt} = 'KRB5':encode('AS-REQ', Req),
	{ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
	ok = gen_udp:send(Sock, "kolanut.cc.uq.edu.au", 88, Pkt),
	recv(Sock).

recv(Sock) ->
	receive
		{udp, Sock, IP, Port, Pkt} ->
			io:format("received ~p\n", [Pkt]),
			case 'KRB5':decode('AS-REP', Pkt) of
				{ok, Req} -> io:format("~s\n", ['KRB5':pretty_print(Req)]);
				_ -> ok
			end,
			case 'KRB5':decode('KRB-ERROR', Pkt) of
				{ok, Err = #'KRB-ERROR'{'e-data' = EData}} ->
					io:format("~s\n", ['KRB5':pretty_print(Err)]),
					case 'KRB5':decode('METHOD-DATA', EData) of
						{ok, PaDatas} ->
							io:format("e-data decoded: ~s\n", ['KRB5':pretty_print(PaDatas)]);
						_ -> ok
					end;
				_ -> ok
			end,
			recv(Sock)
	end.

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
