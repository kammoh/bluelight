package GiftCipher;

import Vector :: *;
import Printf :: *;
import BluelightUtils :: *;
import GiftRound :: *;
import Probe :: *;

export Vector :: *;
export GiftCipher :: *;
export BluelightUtils :: *;

typedef 40 CipherRounds;
// 1, 2, 4, 5, 8, 10, 20, 40
typedef 5 UnrollFactor;

typedef BlockOfSize#(GiftBlockBytes) Block;
typedef Vector#(GiftBlockBytes, Bool) ByteValids;
typedef BlockOfSize#(TDiv#(GiftBlockBytes,2)) HalfBlock;

function HalfBlock double(HalfBlock s);
    HalfBlock tmp;
    /*x^{64} + x^4 + x^3 + x + 1*/
    for (Integer i = 0; i < 8; i = i + 1)
        tmp[i] = {s[i][6:0], s[(i+1) % 8][7]};
    let b = s[0][7];
    tmp[7][1] = tmp[7][1] ^ b;
    tmp[7][3] = tmp[7][3] ^ b;
    tmp[7][4] = tmp[7][4] ^ b;
    return tmp;
endfunction

function HalfBlock triple(HalfBlock s);
    return unpack(pack(double(s)) ^ pack(s));
endfunction

function GiftState toGiftState(Block block);
    GiftState s;
    for (Integer i = 0; i < valueOf(NumBlockWords); i = i + 1)
        s[i] = swapEndian(takeAt(4*i, block));
    return s;
endfunction

function KeyState toKeyState(Block block);
    KeyState s = unpack(pack(block));
    return map(swapEndian, s);
endfunction

function Block giftStateToBlock(GiftState s);
    // big-endian
    s = map(swapEndian, s);
    return unpack(pack(s));
endfunction

// Y[1],Y[2] -> Y[2],Y[1]<<<1
function Block gee(Block s);
    Block tmp = newVector;
    for (Integer i = 0; i < 8; i = i + 1) begin
        tmp[i] = s[8+i];
        tmp[i+8] = {s[i][6:0], s[(i+1) % 8][7]};
    end
    return tmp;
endfunction

function Byte en_byte_xor(Byte b, Bool v, Byte c);
    return (v ? b : 0) ^ c;
endfunction

// TODO optimize?
function Tuple2#(Block, Block) pho(Block y, Block m, ByteValids valids, Bool ct);
    Block c = zipWith3(en_byte_xor, y, valids, m);
    // X[i] = (pad(A[i]) + G(Y[i-1])) + offset
    Block x = unpack(pack(gee(y)) ^ pack(ct ? c : m));
    return tuple2(x, c);
endfunction

function Tuple3#(GiftState,KeyState,RoundConstant) giftRound(GiftState s, KeyState w, RoundConstant rc);
    Tuple3#(GiftState,KeyState,RoundConstant) x = tuple3(s,w,rc);
    for (Integer i = 0; i < valueOf(UnrollFactor); i = i + 1)
        x = singleRound(tpl_1(x), tpl_2(x), tpl_3(x));
    return x;
endfunction

function GiftState xor_topbar_block(Block s1, HalfBlock s2);
    Block tmp = s1;
    for (Integer i = 0; i < 8; i = i + 1)
        tmp[i] = s1[i] ^ s2[i];
    return toGiftState(tmp);
endfunction

function HalfBlock gen_offset(Block y, HalfBlock delta, Bool isFirstAD, Bool fullBlockMsgNotEmpty, Bool isLastBlock);
    let delta1 = isFirstAD ? take(y) : delta;
    HalfBlock offsetX2 = double(delta1);
    let offsetX3 = unpack(pack(offsetX2) ^ pack(delta1));
    let offsetX9 = triple(offsetX3);
    return isLastBlock ? (fullBlockMsgNotEmpty ? offsetX3 : offsetX9) : offsetX2;
endfunction

endpackage