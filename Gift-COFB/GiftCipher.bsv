package GiftCipher;

import Vector :: *;
import Printf :: *;
import BluelightUtils :: *;
import GiftRound :: *;
import Probe :: *;

// export GiftRound :: *;
export GiftCipher :: *;
export BluelightUtils :: *;
export Vector :: *;

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

typedef struct{
    Bool ct;
    Bool ptct;
    Bool ad;
    Bool npub;
    Bool first;
    Bool last;
    Bool eoi;
} Flags deriving(Bits, Eq, FShow);

typedef enum {
    Idle,
    Permute,
    Squeeze // tag
} State deriving (Bits, Eq, FShow);


interface CipherIfc#(numeric type n_bytes, type flags_type);
    // optional operation-specific initialization
    method Action init(Bool new_key, Bool decrypt, Bool hash);

    method Action storeKey(CoreWord w);
    // block in/out
    method ActionValue#(BlockOfSize#(n_bytes)) blockUp(BlockOfSize#(n_bytes) block, ByteValidsOfSize#(n_bytes) valids, flags_type flags); 
    // block out
    method ActionValue#(BlockOfSize#(n_bytes)) blockDown;
endinterface

module mkGiftCipher (CipherIfc#(GiftBlockBytes, Flags)) provisos (Mul#(UnrollFactor, perm_cycles, CipherRounds), Add#(a__, 1, UnrollFactor));
    Reg#(GiftState) giftState <- mkRegU;
    Reg#(KeyState) keyState <- mkRegU;
    Reg#(RoundConstant) roundConstant <- mkRegU;
    let state <- mkReg(Idle);
    Reg#(State) postPermuteState <- mkRegU;
    Reg#(HalfBlock) delta <- mkRegU;
    Reg#(Bit#(TLog#(perm_cycles))) roundCounter <- mkRegU;
    Reg#(Bool) emptyM <- mkRegU;

    match {.nextGS, .nextKS, .nextRC} = giftRound(giftState, keyState, roundConstant);

    messageM(sprintf("Gift with UnrollFactor:%d Cycles/Block:%d", valueOf(UnrollFactor), valueOf(perm_cycles)));
    function Action dump_state();
    action
        `ifdef DEBUG
        $write("[bsv] rc=%h S: ", roundConstant);
        for (Integer i = 0; i < 4; i = i + 1)
            $write("%H ", giftState[i]);
        $write("  W: ");
        for (Integer i = 0; i < 8; i = i + 1)
            $write("%H ", keyState[i]);
        $write("  nextKS: ");
        for (Integer i = 0; i < 8; i = i + 1)
            $write("%H ", nextKS[i]);
        $display("");
        `endif
    endaction
    endfunction

    function Action dump_block(String msg, Vector#(n__, Byte) b);
    action
        `ifdef DEBUG
        $write("[bsv] %s ", msg);
        for (Integer i = 0; i < valueOf(n__); i = i + 1)
            $write("%H ", b[i]);
        $display("");
        `endif
    endaction
    endfunction

    (* fire_when_enabled, no_implicit_conditions *)
    rule rl_permutation if (state == Permute);
        giftState <= nextGS;
        roundConstant <= nextRC;
        
        roundCounter <= roundCounter + 1;
        if (roundCounter == fromInteger(valueOf(perm_cycles) - 1)) begin
            state <= postPermuteState;
            KeyState nks = newVector;
            for (Integer i = 0; i < 8; i = i + 1)
                nks[i] = swapEndian(i % 2 == 0 ? rotateRight(nextKS[i], 4'b0) : nextKS[i]);
            keyState <= nks;
        end
        else
            keyState <= nextKS;
    endrule

    method Action init(Bool new_key, Bool decrypt, Bool hash);
    endmethod

    method Action storeKey(CoreWord w) if (state == Idle);
        match {.hi, .lo} = split(w);
        let ks0 = shiftInAtN(keyState,  swapEndian(lo));
        keyState <= shiftInAtN(ks0,  swapEndian(hi));
    endmethod

    method ActionValue#(Block) blockUp(Block block, ByteValids valids, Flags flags) if (state == Idle);
        let y = giftStateToBlock(giftState);
        Bool lastAdEmptyM = flags.ad && flags.last && (emptyM || flags.eoi);
        Bool emptyMsg = emptyM && flags.ptct;

        match {.x, .c} = pho(y, block, valids, flags.ct);

        if(flags.npub)
            emptyM <= flags.eoi; // set and unset, either new or reused key
        else if(flags.ad && flags.eoi)
            emptyM <= True; // don't unset if previously set

        if (flags.npub)
            giftState <= toGiftState(block);
        else begin
            Bool fullBlock = last(valids);
            let delta1 = flags.ad && flags.first ? take(y) : delta;
            HalfBlock offsetX2 = double(delta1);
            let offsetX3 = unpack(pack(offsetX2) ^ pack(delta1));
            let offsetX9 = triple(offsetX3);
            let offset = flags.last ? (fullBlock && !emptyMsg? offsetX3 : offsetX9) : offsetX2;
            
            if(lastAdEmptyM)
                giftState <= toGiftState(x);
            else if(emptyMsg)
                giftState <= xor_topbar_block(giftStateToBlock(giftState), offset);
            else
                giftState <= xor_topbar_block(x, offset);
            delta <= offset;
        end
        roundConstant <= fromInteger(1);
        if (!lastAdEmptyM)
            state <= Permute;
        postPermuteState <= flags.last && flags.ptct ? Squeeze : Idle;
        roundCounter <= 0;

        return c;
    endmethod

    method ActionValue#(Block) blockDown if (state == Squeeze);
        state <= Idle;
        return giftStateToBlock(giftState);
    endmethod
endmodule

endpackage