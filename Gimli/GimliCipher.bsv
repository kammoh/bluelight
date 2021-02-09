package GimliCipher;

import Printf :: *;
import BluelightUtils :: *;
import GimliRound :: *;

export BluelightUtils :: *;
export GimliRound :: *;
export GimliCipher :: *;

// 1, 2, 3, 4, 6, 8, 12, 24 recommended: high speed: 2, 4, (maybe 6, 8), low area: 1, 2
typedef 4 UnrollFactor;
typedef TDiv#(CipherRounds, UnrollFactor) NumRounds;

typedef BlockOfSize#(GimliBlockBytes) Block;
typedef Vector#(GimliBlockBytes, Bool) ByteValids;

typedef struct{
    Bool key;
    Bool ct;
    Bool ad;
    Bool npub;
    Bool hash;
    Bool first;
    Bool last;
} Flags deriving(Bits, Eq, FShow);

typedef enum {
    Idle,
    GetKey2,
    GetNpub,
    Permute,
    Squeeze2, // 1/2 (digest)
    Squeeze1  // 2/2 (digest) or 1/1 (tag)
} State deriving (Bits, Eq, FShow);

(* default_clock_osc = "clk",
   default_reset = "rst" *)
module mkGimliCipher (CipherIfc#(GimliBlockBytes, Flags)) provisos (Mul#(UnrollFactor, perm_cycles__, CipherRounds));
    Reg#(GimliState) gimliState <- mkRegU;
    let state <- mkReg(Idle);
    Reg#(State) postPermuteState <- mkRegU;
    Reg#(Round) roundCounter <- mkRegU;
    let unrollFactor = valueOf(UnrollFactor);
    let roundStep = fromInteger(unrollFactor);
    let roundMax = fromInteger(valueOf(CipherRounds));
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

    method ActionValue#(Block) blockUp(Block bytes_block, ByteValids valids, Flags flags) if (state == Idle || state == GetKey2 || state == GetNpub);
        GimliBlock block = toChunks(bytes_block);
        GimliBlock xoredBlock = newVector;
        GimliState absorbedState = gimliState;
        for (Integer j = 0; j < 4; j = j + 1) 
            for (Integer k = 0; k < 4; k = k + 1) begin
                xoredBlock[j][k] = gimliState[0][j][k] ^ block[j][k];
                absorbedState[0][j][k] = (flags.ct && valids[4*j + k]) ? block[j][k] : xoredBlock[j][k];
            end
        absorbedState[2][3][3][0] = gimliState[2][3][3][0] ^ pack(flags.last && !flags.key && !flags.npub);
        if (state == GetKey2) begin
            gimliState[2] <= block;
            state <= GetNpub;
        end else begin
            if (flags.key) begin
                gimliState[1] <= block;
                state <= GetKey2;
            end else begin
                if (flags.hash && flags.first)
                    gimliState <= unpack({7'b0, pack(flags.last), zeroExtend(pack(block))});
                else if (flags.npub)
                    gimliState[0] <= block;
                else // absorb (or replace)
                    gimliState <= absorbedState;
                state <= Permute;
                postPermuteState <= (flags.last && !flags.npub && !flags.ad) ? (flags.hash ? Squeeze2 : Squeeze1) : Idle;
                roundCounter <= roundMax;
            end
        end
        return concat(xoredBlock);
    endmethod

    method ActionValue#(Block) blockDown if (state == Squeeze2 || state == Squeeze1);
        state <= (state == Squeeze2) ? Permute : Idle;
        postPermuteState <= Squeeze1;
        roundCounter <= roundMax;
        return concat(gimliState[0]);
    endmethod
endmodule

endpackage