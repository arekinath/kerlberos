-module(cts).

-export([encrypt/4, decrypt/4]).

block_size(aes_cbc128) -> 16;
block_size(aes_cbc256) -> 16;
block_size(des3_cbc) -> 8;
block_size(des_cbc) -> 8.

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
    Padded = <<Plain/binary, 0:(BlockSize - Remainder)/unit:8>>,
    Pn_1 = binary:part(Padded, {(Blocks - 2)*BlockSize, BlockSize}),
    Xn_1 = crypto:exor(Cn_2, Pn_1),
    En_1 = crypto:block_encrypt(Type, Key, <<0:BlockSize/unit:8>>, Xn_1),
    Cn = binary:part(En_1, {0, Ln}),
    P = binary:part(Padded, {(Blocks - 1)*BlockSize, BlockSize}),
    Dn = crypto:exor(En_1, P),
    Cn_1 = crypto:block_encrypt(Type, Key, <<0:BlockSize/unit:8>>, Dn),
    <<CBCPart/binary, Cn_1/binary, Cn/binary>>.

decrypt(Type, Key, IV, Cipher) ->
    ok.
