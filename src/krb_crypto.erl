%% kerlberos
%%
%% Copyright (c) 2015, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc kerberos crypto module (based on rfc3961/3962).
-module(krb_crypto).
-export([
	string_to_key/3,
	random_to_key/2,
	encrypt/3, encrypt/4,
	decrypt/3, decrypt/4,
	atom_to_etype/1,
	etype_to_atom/1]).

-export([crc/1, crc/2]).

-type etype() :: des_crc | des_md4 | des_md5 | des3_md5 | des3_sha1 | aes128_hmac_sha1 | aes256_hmac_sha1 | rc4_hmac | rc4_hmac_exp | des3_sha1_nokd.

-spec etype_to_atom(integer()) -> etype().
etype_to_atom(1) -> des_crc;
etype_to_atom(2) -> des_md4;
etype_to_atom(3) -> des_md5;
etype_to_atom(5) -> des3_md5;
etype_to_atom(7) -> des3_sha1_nokd; % deprecated version
etype_to_atom(16) -> des3_sha1;
etype_to_atom(17) -> aes128_hmac_sha1;
etype_to_atom(18) -> aes256_hmac_sha1;
etype_to_atom(23) -> rc4_hmac;
etype_to_atom(24) -> rc4_hmac_exp;
etype_to_atom(_) -> error(unknown_etype).

-spec atom_to_etype(etype()) -> integer().
atom_to_etype(des_crc) -> 1;
atom_to_etype(des_md4) -> 2;
atom_to_etype(des_md5) -> 3;
atom_to_etype(des3_md5) -> 5;
atom_to_etype(des3_sha1_nokd) -> 7; % deprecated
atom_to_etype(des3_sha1) -> 16;
atom_to_etype(aes128_hmac_sha1) -> 17;
atom_to_etype(aes256_hmac_sha1) -> 18;
atom_to_etype(rc4_hmac) -> 23;
atom_to_etype(rc4_hmac_exp) -> 24;
atom_to_etype(_) -> error(unknown_etype).

-spec encrypt(etype(), binary(), binary()) -> binary().
encrypt(Etype, Key, Data) -> encrypt(Etype, Key, Data, []).

-type cipher_option() :: {usage, integer()}.
-type cipher_options() :: [cipher_option()].

-spec encrypt(etype(), binary(), binary(), cipher_options()) -> binary().
encrypt(des_crc, Key, Data, _Opts) ->
	encrypt_orig(des_cbc, {?MODULE, crc, []}, 4, 8, Key, Key, Data);
encrypt(des_md4, Key, Data, _Opts) ->
	encrypt_orig(des_cbc, {crypto, hash, [md4]}, 16, 8, Key, <<0:64>>, Data);
encrypt(des_md5, Key, Data, _Opts) ->
	encrypt_orig(des_cbc, {crypto, hash, [md5]}, 16, 8, Key, <<0:64>>, Data);
encrypt(aes128_hmac_sha1, Key, Data, Opts) ->
	Usage = proplists:get_value(usage, Opts, 1),
	Triad = base_key_to_triad(aes_cbc128, Key, Usage),
	encrypt_cts_hmac(aes_cbc128, sha, 12, 16, Triad, <<0:128>>, Data);
encrypt(aes256_hmac_sha1, Key, Data, Opts) ->
	Usage = proplists:get_value(usage, Opts, 1),
	Triad = base_key_to_triad(aes_cbc256, Key, Usage),
	encrypt_cts_hmac(aes_cbc256, sha, 12, 16, Triad, <<0:128>>, Data);
encrypt(rc4_hmac, Key, Data, Opts) ->
    T = ms_usage_map(proplists:get_value(usage, Opts, 1)),
    K1 = crypto:hmac(md5, Key, <<T:32/little>>),
    K2 = K1,
    Confounder = crypto:rand_bytes(8),
    PreMAC = <<Confounder/binary, Data/binary>>,
    MAC = crypto:hmac(md5, K2, PreMAC),
    K3 = crypto:hmac(md5, K1, MAC),
    State0 = crypto:stream_init(rc4, K3),
    {State1, ConfEnc} = crypto:stream_encrypt(State0, Confounder),
    {_, DataEnc} = crypto:stream_encrypt(State1, Data),
    <<MAC/binary, ConfEnc/binary, DataEnc/binary>>;
encrypt(E, _, _, _) -> error({unknown_etype, E}).

-spec decrypt(etype(), binary(), binary()) -> binary().
decrypt(Etype, Key, Data) -> encrypt(Etype, Key, Data, []).

decrypt(des_crc, Key, Data, _Opts) ->
	decrypt_orig(des_cbc, {?MODULE, crc, []}, 4, 8, Key, Key, Data);
decrypt(des_md4, Key, Data, _Opts) ->
	decrypt_orig(des_cbc, {crypto, hash, [md4]}, 16, 8, Key, <<0:64>>, Data);
decrypt(des_md5, Key, Data, _Opts) ->
	decrypt_orig(des_cbc, {crypto, hash, [md5]}, 16, 8, Key, <<0:64>>, Data);
decrypt(aes128_hmac_sha1, Key, Data, Opts) ->
	Usage = proplists:get_value(usage, Opts, 1),
	Triad = base_key_to_triad(aes_cbc128, Key, Usage),
	decrypt_cts_hmac(aes_cbc128, sha, 12, 16, Triad, <<0:128>>, Data);
decrypt(aes256_hmac_sha1, Key, Data, Opts) ->
	Usage = proplists:get_value(usage, Opts, 1),
	Triad = base_key_to_triad(aes_cbc256, Key, Usage),
	decrypt_cts_hmac(aes_cbc256, sha, 12, 16, Triad, <<0:128>>, Data);
decrypt(rc4_hmac, Key, Data, Opts) ->
    T = ms_usage_map(proplists:get_value(usage, Opts, 1)),
    K1 = crypto:hmac(md5, Key, <<T:32/little>>),
    K2 = K1,
    <<MAC:16/binary, ConfEnc:16/binary, DataEnc/binary>> = Data,
    K3 = crypto:hmac(md5, K1, MAC),
    State0 = crypto:stream_init(rc4, K3),
    {State1, Confounder} = crypto:stream_decrypt(State0, ConfEnc),
    {_, Plain} = crypto:stream_decrypt(State1, DataEnc),
    PreMAC = <<Confounder/binary, Plain/binary>>,
    MAC = crypto:hmac(md5, K2, PreMAC),
    Plain;
decrypt(E, _, _, _) -> error({unknown_etype, E}).

-type protocol_key() :: {Kc :: binary(), Ke :: binary(), Ki :: binary()}.
-spec encrypt_cts_hmac(atom(), atom(), integer(), integer(), protocol_key(), binary(), binary()) -> binary().
encrypt_cts_hmac(Cipher, MacType, MacLength, BlockSize, {_Kc, Ke, Ki}, IV, Data) ->
	Confounder = crypto:rand_bytes(BlockSize),
	PreMAC = <<Confounder/binary, Data/binary>>,
	HMAC = crypto:hmac(MacType, Ki, PreMAC, MacLength),
	Enc = crypto_cts:encrypt(Cipher, Ke, IV, PreMAC),
	<<Enc/binary, HMAC/binary>>.

-spec encrypt_orig(atom(), mfa(), integer(), integer(), binary(), binary(), binary()) -> binary().
encrypt_orig(Cipher, MacFun, MacLength, BlockSize, Key, IV, Data) ->
	Confounder = crypto:rand_bytes(BlockSize),
	PreMAC = pad_block(<<Confounder/binary, 0:MacLength/unit:8, Data/binary>>, BlockSize),
	{MacM, MacF, MacA} = MacFun,
	MAC = binary:part(erlang:apply(MacM, MacF, MacA ++ [PreMAC]), {0, MacLength}),
	PostMAC = pad_block(<<Confounder/binary, MAC/binary, Data/binary>>, BlockSize),
	crypto:block_encrypt(Cipher, Key, IV, PostMAC).

-spec decrypt_cts_hmac(atom(), atom(), integer(), integer(), protocol_key(), binary(), binary()) -> binary().
decrypt_cts_hmac(Cipher, MacType, MacLength, BlockSize, {_Kc, Ke, Ki}, IV, Data) ->
	EncLen = byte_size(Data) - MacLength,
	<<Enc:EncLen/binary, HMAC/binary>> = Data,
	PreMAC = crypto_cts:decrypt(Cipher, Ke, IV, Enc),
	HMAC = crypto:hmac(MacType, Ki, PreMAC, MacLength),
	<<_Confounder:BlockSize/binary, Plain/binary>> = PreMAC,
	Plain.

-spec decrypt_orig(atom(), mfa(), integer(), integer(), binary(), binary(), binary()) -> binary().
decrypt_orig(Cipher, MacFun, MacLength, BlockSize, Key, IV, Data) ->
	PostMAC = crypto:block_decrypt(Cipher, Key, IV, Data),
	<<Confounder:BlockSize/binary, MAC:MacLength/binary, PaddedData/binary>> = PostMAC,
	PreMAC = <<Confounder/binary, 0:MacLength/unit:8, PaddedData/binary>>,
	{MacM, MacF, MacA} = MacFun,
	MAC = binary:part(erlang:apply(MacM, MacF, MacA ++ [PreMAC]), {0, MacLength}),
	PaddedData.

-spec base_key_to_triad(atom(), binary(), integer()) -> protocol_key().
base_key_to_triad(Cipher, BaseKey, Usage) ->
	Kc = dk(Cipher, BaseKey, <<Usage:32/big, 16#99>>),
	Ke = dk(Cipher, BaseKey, <<Usage:32/big, 16#aa>>),
	Ki = dk(Cipher, BaseKey, <<Usage:32/big, 16#55>>),
	{Kc, Ke, Ki}.

-spec dk(atom(), binary(), binary()) -> binary().
dk(Cipher, BaseKey, Constant) ->
	BlockSize = crypto_cts:block_size(Cipher) * 8,
	make_dk_bits(Cipher, nfold(BlockSize, Constant), <<>>, bit_size(BaseKey), BaseKey, <<0:BlockSize>>).

to_56bstr(B) ->
	<< <<Low:7>> || <<_:1,Low:7>> <= B >>.

ms_usage_map(3) -> 8;
ms_usage_map(9) -> 8;
ms_usage_map(N) -> N.

des_add_parity(B) ->
	<< <<N:7,(odd_parity(N)):1>> || <<N:7>> <= B >>.
des_fix_parity(B) ->
	<< <<N:7,(odd_parity(N)):1>> || <<N:7,_:1>> <= B >>.
odd_parity(N) ->
    Set = length([ 1 || <<1:1>> <= <<N>> ]),
    if (Set rem 2 == 1) -> 0; true -> 1 end.

bitrev(<<>>) -> <<>>;
bitrev(<<N:1>>) -> <<N:1>>;
bitrev(<<N:1, Rest/bitstring>>) ->
	RestRev = bitrev(Rest),
	<<RestRev/bitstring, N:1>>.

-spec binxor(bitstring(), bitstring()) -> bitstring().
binxor(<<>>, <<>>) -> <<>>;
binxor(<<N:64>>, <<M:64>>) -> X = N bxor M, <<X:64>>;
binxor(<<N:56>>, <<M:56>>) -> X = N bxor M, <<X:56>>;
binxor(<<N:8, RestN/bitstring>>, <<M:8, RestM/bitstring>>) ->
	Rest = binxor(RestN, RestM),
	X = N bxor M,
	<<X:8, Rest/bitstring>>;
binxor(<<N:1, RestN/bitstring>>, <<M:1, RestM/bitstring>>) ->
	Rest = binxor(RestN, RestM),
	X = N bxor M,
	<<X:1, Rest/bitstring>>.

des_string_to_key_stage(State, _, <<>>) ->
	State;
des_string_to_key_stage(State, Odd, <<Block:8/binary, Rest/binary>>) ->
	As56 = to_56bstr(Block),
	Xor = if (Odd) -> As56; (not Odd) -> bitrev(As56) end,
	State2 = binxor(State, Xor),
	des_string_to_key_stage(State2, (not Odd), Rest).

ms_string_to_key(Bin) ->
    crypto:hash(md4, unicode:characters_to_binary(Bin, utf8, {utf16, little})).

pad_block(B) -> pad_block(B, 8).
pad_block(B, 1) -> B;
pad_block(B, N) ->
	PadSize = N - (byte_size(B) rem N),
	<<B/binary, 0:PadSize/unit:8>>.

-spec string_to_key(etype(), binary(), binary()) -> binary().
string_to_key(des_crc, String, Salt) -> des_string_to_key(String, Salt);
string_to_key(des_md4, String, Salt) -> des_string_to_key(String, Salt);
string_to_key(des_md5, String, Salt) -> des_string_to_key(String, Salt);
string_to_key(aes128_hmac_sha1, String, Salt) -> aes_string_to_key(aes_cbc128, 16, String, Salt);
string_to_key(aes256_hmac_sha1, String, Salt) -> aes_string_to_key(aes_cbc256, 32, String, Salt);
string_to_key(rc4_hmac, String, Salt) -> ms_string_to_key(String);
string_to_key(E, _, _) -> error({unknown_etype, E}).

-spec random_to_key(etype(), binary()) -> binary().
random_to_key(des_crc, Data) -> des_random_to_key(Data, Data);
random_to_key(des_md4, Data) -> des_random_to_key(<<0:64>>, Data);
random_to_key(des_md5, Data) -> des_random_to_key(<<0:64>>, Data);
random_to_key(aes128_hmac_sha1, Data) -> aes_random_to_key(aes_cbc128, Data);
random_to_key(aes256_hmac_sha1, Data) -> aes_random_to_key(aes_cbc256, Data);
random_to_key(E, _) -> error({unknown_etype, E}).

-spec make_dk_bits(atom(), binary(), bitstring(), integer(), binary(), binary()) -> bitstring().
make_dk_bits(_Cipher, _Source, SoFar, N, _Key, _IV) when bit_size(SoFar) >= N ->
	<<Ret:N/bitstring, _/bitstring>> = SoFar,
	Ret;
make_dk_bits(Cipher, Source, SoFar, N, Key, IV) ->
	LastBlock = case SoFar of
		<<>> -> Source;
		_ -> binary:part(SoFar, {byte_size(SoFar), -1 * crypto_cts:block_size(Cipher)})
	end,
	Block = crypto:block_encrypt(Cipher, Key, IV, LastBlock),
	make_dk_bits(Cipher, Source, <<SoFar/binary,Block/binary>>, N, Key, IV).

des_random_to_key(IV, Data) ->
	WithoutParity = make_dk_bits(des_cbc, nfold(56, <<"kerberos">>), <<>>, 56, Data, IV),
	des_add_parity(WithoutParity).

aes_random_to_key(Cipher, Data) ->
	dk(Cipher, Data, <<"kerberos">>).

des_string_to_key(String, Salt) ->
	Padded = pad_block(<<String/binary, Salt/binary>>),
	RawKey = des_string_to_key_stage(<<0:56>>, true, Padded),
	RawKeyParity = des_add_parity(RawKey),
	Crypt = crypto:block_encrypt(des_cbc, RawKeyParity, RawKeyParity, Padded),
	LastBlock = binary:part(Crypt, {byte_size(Crypt), -8}),
	des_fix_parity(LastBlock).

aes_string_to_key(Cipher, Size, String, Salt) ->
	{ok, KdfOut} = pbkdf2:pbkdf2(sha, String, Salt, 4096, Size),
	aes_random_to_key(Cipher, KdfOut).

-spec nfold(integer(), bitstring()) -> bitstring().
nfold(N, X) when is_integer(N) and is_binary(X) ->
    RepLen = lcm(N, bit_size(X)),
    Blocks = nfold_rep(<<>>, X, RepLen),
    nfold_sum(<<0:N>>, Blocks, N).

nfold_rep(SoFar, _Block, N) when bit_size(SoFar) >= N -> SoFar;
nfold_rep(SoFar0, Block0, N) ->
    SoFar = <<SoFar0/binary, Block0/binary>>,
    HeadSize = bit_size(Block0) - 13,
    <<Head:HeadSize/bitstring, Tail/bitstring>> = Block0,
    Block = <<Tail/bitstring, Head/bitstring>>,
    nfold_rep(SoFar, Block, N).

nfold_sum(Sum, <<>>, _N) -> Sum;
nfold_sum(Sum, Blocks, N) ->
    <<X0:N/big>> = Sum,
    <<X:N/big, Rest/bitstring>> = Blocks,
    nfold_sum(<<(X0 + X):N/big>>, Rest, N).

-spec gcd(integer(), integer()) -> integer().
gcd(A, 0) -> A;
gcd(A, B) -> gcd(B, A rem B).
-spec lcm(integer(), integer()) -> integer().
lcm(A, B) -> abs(A*B div gcd(A,B)).

-define(crc_table, {16#00000000, 16#77073096, 16#ee0e612c, 16#990951ba, 16#076dc419, 16#706af48f,
  16#e963a535, 16#9e6495a3, 16#0edb8832, 16#79dcb8a4, 16#e0d5e91e, 16#97d2d988,
  16#09b64c2b, 16#7eb17cbd, 16#e7b82d07, 16#90bf1d91, 16#1db71064, 16#6ab020f2,
  16#f3b97148, 16#84be41de, 16#1adad47d, 16#6ddde4eb, 16#f4d4b551, 16#83d385c7,
  16#136c9856, 16#646ba8c0, 16#fd62f97a, 16#8a65c9ec, 16#14015c4f, 16#63066cd9,
  16#fa0f3d63, 16#8d080df5, 16#3b6e20c8, 16#4c69105e, 16#d56041e4, 16#a2677172,
  16#3c03e4d1, 16#4b04d447, 16#d20d85fd, 16#a50ab56b, 16#35b5a8fa, 16#42b2986c,
  16#dbbbc9d6, 16#acbcf940, 16#32d86ce3, 16#45df5c75, 16#dcd60dcf, 16#abd13d59,
  16#26d930ac, 16#51de003a, 16#c8d75180, 16#bfd06116, 16#21b4f4b5, 16#56b3c423,
  16#cfba9599, 16#b8bda50f, 16#2802b89e, 16#5f058808, 16#c60cd9b2, 16#b10be924,
  16#2f6f7c87, 16#58684c11, 16#c1611dab, 16#b6662d3d, 16#76dc4190, 16#01db7106,
  16#98d220bc, 16#efd5102a, 16#71b18589, 16#06b6b51f, 16#9fbfe4a5, 16#e8b8d433,
  16#7807c9a2, 16#0f00f934, 16#9609a88e, 16#e10e9818, 16#7f6a0dbb, 16#086d3d2d,
  16#91646c97, 16#e6635c01, 16#6b6b51f4, 16#1c6c6162, 16#856530d8, 16#f262004e,
  16#6c0695ed, 16#1b01a57b, 16#8208f4c1, 16#f50fc457, 16#65b0d9c6, 16#12b7e950,
  16#8bbeb8ea, 16#fcb9887c, 16#62dd1ddf, 16#15da2d49, 16#8cd37cf3, 16#fbd44c65,
  16#4db26158, 16#3ab551ce, 16#a3bc0074, 16#d4bb30e2, 16#4adfa541, 16#3dd895d7,
  16#a4d1c46d, 16#d3d6f4fb, 16#4369e96a, 16#346ed9fc, 16#ad678846, 16#da60b8d0,
  16#44042d73, 16#33031de5, 16#aa0a4c5f, 16#dd0d7cc9, 16#5005713c, 16#270241aa,
  16#be0b1010, 16#c90c2086, 16#5768b525, 16#206f85b3, 16#b966d409, 16#ce61e49f,
  16#5edef90e, 16#29d9c998, 16#b0d09822, 16#c7d7a8b4, 16#59b33d17, 16#2eb40d81,
  16#b7bd5c3b, 16#c0ba6cad, 16#edb88320, 16#9abfb3b6, 16#03b6e20c, 16#74b1d29a,
  16#ead54739, 16#9dd277af, 16#04db2615, 16#73dc1683, 16#e3630b12, 16#94643b84,
  16#0d6d6a3e, 16#7a6a5aa8, 16#e40ecf0b, 16#9309ff9d, 16#0a00ae27, 16#7d079eb1,
  16#f00f9344, 16#8708a3d2, 16#1e01f268, 16#6906c2fe, 16#f762575d, 16#806567cb,
  16#196c3671, 16#6e6b06e7, 16#fed41b76, 16#89d32be0, 16#10da7a5a, 16#67dd4acc,
  16#f9b9df6f, 16#8ebeeff9, 16#17b7be43, 16#60b08ed5, 16#d6d6a3e8, 16#a1d1937e,
  16#38d8c2c4, 16#4fdff252, 16#d1bb67f1, 16#a6bc5767, 16#3fb506dd, 16#48b2364b,
  16#d80d2bda, 16#af0a1b4c, 16#36034af6, 16#41047a60, 16#df60efc3, 16#a867df55,
  16#316e8eef, 16#4669be79, 16#cb61b38c, 16#bc66831a, 16#256fd2a0, 16#5268e236,
  16#cc0c7795, 16#bb0b4703, 16#220216b9, 16#5505262f, 16#c5ba3bbe, 16#b2bd0b28,
  16#2bb45a92, 16#5cb36a04, 16#c2d7ffa7, 16#b5d0cf31, 16#2cd99e8b, 16#5bdeae1d,
  16#9b64c2b0, 16#ec63f226, 16#756aa39c, 16#026d930a, 16#9c0906a9, 16#eb0e363f,
  16#72076785, 16#05005713, 16#95bf4a82, 16#e2b87a14, 16#7bb12bae, 16#0cb61b38,
  16#92d28e9b, 16#e5d5be0d, 16#7cdcefb7, 16#0bdbdf21, 16#86d3d2d4, 16#f1d4e242,
  16#68ddb3f8, 16#1fda836e, 16#81be16cd, 16#f6b9265b, 16#6fb077e1, 16#18b74777,
  16#88085ae6, 16#ff0f6a70, 16#66063bca, 16#11010b5c, 16#8f659eff, 16#f862ae69,
  16#616bffd3, 16#166ccf45, 16#a00ae278, 16#d70dd2ee, 16#4e048354, 16#3903b3c2,
  16#a7672661, 16#d06016f7, 16#4969474d, 16#3e6e77db, 16#aed16a4a, 16#d9d65adc,
  16#40df0b66, 16#37d83bf0, 16#a9bcae53, 16#debb9ec5, 16#47b2cf7f, 16#30b5ffe9,
  16#bdbdf21c, 16#cabac28a, 16#53b39330, 16#24b4a3a6, 16#bad03605, 16#cdd70693,
  16#54de5729, 16#23d967bf, 16#b3667a2e, 16#c4614ab8, 16#5d681b02, 16#2a6f2b94,
  16#b40bbe37, 16#c30c8ea1, 16#5a05df1b, 16#2d02ef8d}).

-spec crc(binary()) -> binary().
crc(B) when is_binary(B) -> << (crc(0, 0, B)):32/little >>.

-spec crc(integer(), binary()) -> integer().
crc(State, B) -> crc(State, 0, B).

-spec crc(integer(), integer(), binary()) -> integer().
crc(State, N, B) when N >= byte_size(B) ->
	State;
crc(State, N, B) ->
	Idx = (State bxor binary:at(B, N)) band 16#ff,
	State2 = element(Idx + 1, ?crc_table) bxor (State bsr 8),
	crc(State2, N+1, B).
