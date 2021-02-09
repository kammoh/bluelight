package GiftRound;

import Vector :: *;
import Printf :: *;
import BluelightUtils :: *;

typedef 128 NumBlockBits;
typedef TDiv#(NumBlockBits, SizeOf#(Byte)) GiftBlockBytes;
typedef Bit#(32) SWord;
typedef TDiv#(NumBlockBits, SizeOf#(SWord)) NumBlockWords;
typedef Bit#(16) KWord;
typedef 8 NumKeyStateWords;
typedef Vector#(NumKeyStateWords, KWord) KeyState;
typedef Vector#(NumBlockWords, SWord) GiftState;

typedef Bit#(6) RoundConstant;

function BlockOfSize#(GiftBlockBytes) giftStateToBlock(GiftState s);
    // big-endian
    return unpack(pack(map(swapEndian, s)));
endfunction

function GiftState subCells (GiftState s);
    s[1] = s[1] ^ (s[0] & s[2]);
    s[0] = s[0] ^ (s[1] & s[3]);
    s[2] = s[2] ^ (s[0] | s[1]);
    s[3] = s[3] ^ s[2];
    s[1] = s[1] ^ s[3];
    s[3] = ~s[3];
    s[2] = s[2] ^ (s[0] & s[1]);
    return cons(s[3], cons(s[1], cons(s[2], cons(s[0], nil))));
endfunction

function GiftState permBits (GiftState s);
    GiftState ns = newVector;
    for (Integer i = 0; i < 4; i = i + 1)
        for (Integer j = 0; j < 4; j = j + 1)
            for(Integer b = 0; b < 8; b = b + 1)
                ns[i][b + 8*((i + 4 - j) % 4)] = s[i][4*b + j];
    return ns;
endfunction

function GiftState addRoundKey(GiftState s, KeyState w, Bit#(6) rc);
    let u = {w[2], w[3]};
    let v = {w[6], w[7]};
    s[2] = s[2] ^ u;
    s[1] = s[1] ^ v;
    s[3] = s[3] ^ {1'b1, zeroExtend(rc)};
    return s;
endfunction

function Tuple3#(GiftState,KeyState,RoundConstant) singleRound(GiftState s, KeyState w, RoundConstant rc);
    s = subCells(s);
    s = permBits(s);
    s = addRoundKey(s, w, rc);
    rc = {rc[4:0], rc[5] ~^ rc[4]};
    w = cons(rotateRight(w[6], 2'b0), cons(rotateRight(w[7], 12'b0), take(w)));
    return tuple3(s, w, rc);
endfunction

endpackage