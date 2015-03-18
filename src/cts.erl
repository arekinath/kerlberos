-module(cts).

-export([encrypt/4, decrypt/4]).
-export([block_size/1]).

-type cipher() :: aes_cbc128 | aes_cbc256 | des3_cbc | des_cbc.

-spec block_size(cipher()) -> integer().
block_size(aes_cbc128) -> 16;
block_size(aes_cbc256) -> 16;
block_size(des3_cbc) -> 8;
block_size(des_cbc) -> 8.

-spec encrypt(cipher(), binary(), binary(), binary()) -> binary().
encrypt(Type, Key, IV0, Plain) ->
    BlockSize = block_size(Type),
    WholeBlocks = byte_size(Plain) div BlockSize,
    Remainder = byte_size(Plain) rem BlockSize,
    Ln = if (Remainder > 0) -> Remainder; true -> BlockSize end,
    Blocks = if (Remainder > 0) -> WholeBlocks + 1; true -> WholeBlocks end,
    {CBCPart, Cn_2} = case Blocks of
        B when B > 2 ->
            Initial = crypto:block_encrypt(Type, Key, IV0,
                binary:part(Plain, {0, (Blocks - 2)*BlockSize})),
            {Initial, binary:part(Initial, {byte_size(Initial), -1 * BlockSize})};
        _ ->
            {<<>>, IV0}
    end,
    Padded = <<Plain/binary, 0:(BlockSize - Ln)/unit:8>>,
    Pn_1 = binary:part(Padded, {(Blocks - 2)*BlockSize, BlockSize}),
    Xn_1 = crypto:exor(Cn_2, Pn_1),
    En_1 = crypto:block_encrypt(Type, Key, <<0:BlockSize/unit:8>>, Xn_1),
    Cn = binary:part(En_1, {0, Ln}),
    P = binary:part(Padded, {(Blocks - 1)*BlockSize, BlockSize}),
    Dn = crypto:exor(En_1, P),
    Cn_1 = crypto:block_encrypt(Type, Key, <<0:BlockSize/unit:8>>, Dn),
    <<CBCPart/binary, Cn_1/binary, Cn/binary>>.

-spec decrypt(cipher(), binary(), binary(), binary()) -> binary().
decrypt(Type, Key, IV0, Cipher) ->
    BlockSize = block_size(Type),
    WholeBlocks = byte_size(Cipher) div BlockSize,
    Remainder = byte_size(Cipher) rem BlockSize,
    Ln = if (Remainder > 0) -> Remainder; true -> BlockSize end,
    Blocks = if (Remainder > 0) -> WholeBlocks + 1; true -> WholeBlocks end,
    {CBCPart, Cn_2} = case Blocks of
        B when B > 2 ->
            Initial = crypto:block_decrypt(Type, Key, IV0,
                binary:part(Cipher, {0, (Blocks - 2)*BlockSize})),
            {Initial, binary:part(Cipher, {(Blocks - 3)*BlockSize, BlockSize})};
        _ ->
            {<<>>, IV0}
    end,
    Cn_1 = binary:part(Cipher, {(Blocks - 2)*BlockSize, BlockSize}),
    Cn = binary:part(Cipher, {(Blocks - 1)*BlockSize, Ln}),
    Dn = crypto:block_decrypt(Type, Key, <<0:BlockSize/unit:8>>, Cn_1),
    C = <<Cn/binary, 0:(BlockSize - Ln)/unit:8>>,
    Xn = crypto:exor(Dn, C),
    <<Pn:Ln/binary, XnTail/binary>> = Xn,
    En_1 = <<Cn/binary, XnTail/binary>>,
    Xn_1 = crypto:block_decrypt(Type, Key, <<0:BlockSize/unit:8>>, En_1),
    Pn_1 = crypto:exor(Xn_1, Cn_2),
    <<CBCPart/binary, Pn_1/binary, Pn/binary>>.

