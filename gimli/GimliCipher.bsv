package GimliCipher;

import GetPut :: *;
import FIFO :: *;
import Vector :: *;
import Printf :: *;

typedef Bit#(8) Byte;
typedef Vector#(4, Byte) Word;
typedef Vector#(3, Vector#(4, Word)) GimliState;

typedef 24 GimliRounds;
typedef Bit#(TLog#(GimliRounds)) Round;

// 1, 2, 3, 4, 6, 8, 12, 24
// high speed: 2, 4, 6, (maybe 8)
// low area:   1, 2
typedef 6 UnrollFactor;
typedef TDiv#(GimliRounds, UnrollFactor) NumRounds;

// function Action dump_state(String msg, GimliState s);
//     action
//         $write(msg, " ");
//         for (Integer i = 0; i < 3; i = i + 1)
//             for (Integer j = 0; j < 4; j = j + 1)
//                 $write("0x%h ", s[i][j]);
//         $display("");
//     endaction
// endfunction

typedef enum {
    Idle,
    GetKey2,
    GetNpub,
    Permute,
    Squeeze2, // 1/2 (digest)
    Squeeze1  // 2/2 (digest) or 1/1 (tag)
} State deriving (Bits, Eq, FShow);

typedef Vector#(4, Word) Block;
typedef Vector#(TMul#(4,4), Bool) ByteValids;

interface CipherIfc;
    // block in/out
    method ActionValue#(Block) bin(Block block, ByteValids valids, Bool key, Bool ct, Bool ad, Bool npub, Bool hash, Bool first, Bool last); 
    // block out
    method ActionValue#(Block) bout; 
endinterface

function Bit#(32) rotateLeft(Word w, Bit#(n) dummy) provisos (Add#(n,m,32));
    Tuple2#(Bit#(n),Bit#(m)) s = split(pack(w));
    return {tpl_2(s), tpl_1(s)};
endfunction

function GimliState spBox(GimliState s);
    GimliState sp = newVector;
    for (Integer j = 0; j <= 3; j = j + 1) begin
        let x = rotateLeft(s[0][j], 24'b0);
        let y = rotateLeft(s[1][j], 9'b0);
        let z = pack(s[2][j]);
        sp[2][j] = unpack( x ^ (z << 1) ^ ((y & z) << 2) );
        sp[1][j] = unpack( y ^    x     ^ ((x | z) << 1) );
        sp[0][j] = unpack( z ^    y     ^ ((x & y) << 3) );
    end
    return sp;
endfunction

function GimliState singleRound(GimliState s, Round r);
    GimliState sp = spBox(s);
    let rMod4Is0 = r[1:0] == 0;
    let rMod4Is2 = r[1:0] == 2;
    let small_swap = cons(sp[0][1], cons(sp[0][0], cons(sp[0][3], cons(sp[0][2], nil))));
    if (rMod4Is0)
        sp[0] = small_swap;
    else if (rMod4Is2)
        sp[0] = reverse(small_swap);
    if (rMod4Is0)
        sp[0][0] = unpack( pack(sp[0][0]) ^ {24'h9e3779, zeroExtend(r)} );
    return sp;
endfunction

(* default_clock_osc = "clk",
   default_reset = "rst" *)
module mkGimliCipher (CipherIfc) provisos (Mul#(UnrollFactor, perm_cycles__, GimliRounds));
    Reg#(GimliState) gimliState <- mkRegU;
    let state <- mkReg(Idle);
    Reg#(State) postPermuteState <- mkRegU;
    Reg#(Round) roundCounter <- mkRegU;
    let unrollFactor = valueOf(UnrollFactor);
    let roundStep = fromInteger(unrollFactor);
    let roundMax = fromInteger(valueOf(GimliRounds));
    messageM(sprintf("Gimli with UnrollFactor:%d Cycles/Block:%d", unrollFactor, valueOf(perm_cycles__)));

    function GimliState gimliRound(GimliState currentState);
        GimliState s = currentState;
        for (Integer i = 0; i < unrollFactor; i = i + 1)
            s = singleRound(s, roundCounter - fromInteger(i));
        return s;
    endfunction

    (* fire_when_enabled, no_implicit_conditions *)
    rule rl_permutation if (state == Permute);
        gimliState <= gimliRound(gimliState);
        roundCounter <= roundCounter - roundStep;
        if (roundCounter == roundStep)
            state <= postPermuteState;
    endrule

    method ActionValue#(Block) bin(Block block, ByteValids valids, Bool key, Bool ct, Bool ad, Bool npub, Bool hash, Bool first, Bool last) if (state == Idle || state == GetKey2 || state == GetNpub);
        Block xoredBlock = newVector;
        GimliState absorbedState = gimliState;
        for (Integer j = 0; j < 4; j = j + 1) 
            for (Integer k = 0; k < 4; k = k + 1) begin
                xoredBlock[j][k] = gimliState[0][j][k] ^ block[j][k];
                absorbedState[0][j][k] = (ct && valids[4*j + k]) ? block[j][k] : xoredBlock[j][k];
            end
        absorbedState[2][3][3][0] = gimliState[2][3][3][0] ^ pack(last && !key && !npub);
        
        if (state == GetKey2) begin
            gimliState[2] <= block;
            state <= GetNpub;
        end else begin
            if (key) begin
                gimliState[1] <= block;
                state <= GetKey2;
            end else begin
                if (hash && first)
                    gimliState <= unpack({7'b0, pack(last), zeroExtend(pack(block))});
                else if (npub)
                    gimliState[0] <= block;
                else // absorb (or replace)
                    gimliState <= absorbedState;
                state <= Permute;
                postPermuteState <= (last && !npub && !ad) ? (hash ? Squeeze2 : Squeeze1) : Idle;
                roundCounter <= roundMax;
            end
        end

        return xoredBlock;
    endmethod

    method ActionValue#(Block) bout if (state == Squeeze2 || state == Squeeze1);
        state <= (state == Squeeze2) ? Permute : Idle;
        postPermuteState <= Squeeze1;
        roundCounter <= roundMax;
        return gimliState[0];
    endmethod
endmodule

endpackage