package AsconCipher;

import BluelightUtils :: *;
import CryptoCore :: *;
import AsconRound :: *;
import LwcApi :: *;

// function Action dump_state(String msg, AsconState s);
//     action
//         $write("%24.24s: ", msg);
//         for (Integer i = 0; i < 5; i = i + 1)
//             $write(" x%1.1d=%h", i, s[i]);
//         $display("");
//     endaction
// endfunction

typedef enum {
    Idle,
    LoadKey,
    Absorb,
    Permute,
    Squeeze
} State deriving (Bits, Eq, FShow);

typedef TMul#(RateWords,8) BlockBytes;
typedef BlockOfSize#(BlockBytes) Block;
typedef ByteValidsOfSize#(BlockBytes) ByteValids;

function Vector#(n_words, AsconWord) bytesToWords(Vector#(n_bytes, Byte) bytes) provisos(Mul#(n_words,8,n_bytes));
    Vector#(n_words, AsconWord) x = unpack(pack(bytes));
    return map(swapEndian, x);
endfunction

function AsconWord bytesToWord(Vector#(8, Byte) bytes);
    return swapEndian(pack(bytes));
endfunction

function Vector#(n_bytes, Byte) wordsToBytes(Vector#(n_words, AsconWord) words) provisos(Mul#(n_words,8,n_bytes));
    Vector#(n_words, AsconWord) x = map(swapEndian, words);
    return unpack(pack(x));
endfunction

typedef struct{
    Bool npub;
    Bool ad;
    Bool ptct;
    Bool ct;
    Bool hash;
    Bool first;
    Bool last;
} Flags deriving(Bits, Eq, FShow);

typedef 2 KeyWords;

interface CipherIfc#(numeric type n_bytes, type flags_type);
    // optional operation-specific initialization
    method Action init(OpFlags op);
    
    method Action key(BlockOfSize#(n_bytes) block);

    // method Action storeKey(CoreWord w);
    // block in/out
    method ActionValue#(BlockOfSize#(n_bytes)) absorb(BlockOfSize#(n_bytes) block, ByteValidsOfSize#(n_bytes) valids, flags_type flags); 
    // block out
    method ActionValue#(BlockOfSize#(8)) squeeze;
endinterface

module mkAsconCipher (CipherIfc#(BlockBytes, Flags)) provisos (Mul#(UnrollFactor, pa_cycles, PaRounds),Mul#(UnrollFactor, pb_cycles, PbRounds));
    Reg#(AsconState) asconState <- mkRegU;
    let state <- mkReg(Idle);
    Reg#(State) postPermuteState <- mkRegU;
    Reg#(Vector#(KeyWords,AsconWord)) keyStore <- mkRegU;
    Reg#(Bit#(TLog#(pa_cycles))) roundCounter <- mkRegU;
    Reg#(RoundConstant) roundConstant <- mkRegU;
    Reg#(Bit#(2)) squeezeCounter <- mkRegU; // 2 bits if supports hash, o/w 1 bit
    Reg#(Bit#(1)) loadKeyCounter <- mkRegU; // which part of key is loading
    Reg#(Bit#(1)) loadNonceCounter <- mkRegU;
    Reg#(Bool) squeezeHash <- mkRegU;

    let rateWords = valueOf(RateWords);

    (* fire_when_enabled, no_implicit_conditions *)
    rule rl_permutation if (state == Permute);
        match {.nxtState, .nxtRC} = permutation(asconState, roundConstant);
        asconState <= nxtState;
        roundConstant <= nxtRC;
        roundCounter <= roundCounter + 1;
        if (roundCounter == fromInteger(valueOf(pa_cycles) - 1))
            state <= postPermuteState;
    endrule

    function AsconWord getIV(Bool hash);
        Byte r = {fromInteger(rateWords), 6'b0};
        Byte a = fromInteger(valueOf(PaRounds));
        Byte b = hash ? 0 : fromInteger(valueOf(PbRounds));
        return {pack(!hash), 7'b0, r, a, b, 23'b0, pack(hash), 8'b0};
    endfunction

    function AsconState keyNonceInit(Block npubBlock, Vector#(2, AsconWord) ks);
        // Npub_0: previously copied if rateWords == 1
        AsconState s = asconState;
        s[0] = getIV(False);
        s[1] = ks[0];
        s[2] = ks[1];
        let npub = bytesToWords(npubBlock);
        for (Integer i = 0; i < rateWords; i = i + 1)
            s[5 - rateWords + i] = npub[i];
        return s;
    endfunction

    // Must be called before any operation
    method Action init(OpFlags op) if (state == Idle);
        if(op.hash) begin
            asconState <= unpack(pack(zeroExtend(getIV(True))));
            roundConstant <= initRC(False);
        end
        state <= op.hash ? Permute : op.new_key ? LoadKey : LoadKey;
        postPermuteState <= Absorb;
        roundCounter <= 0;
        loadKeyCounter <= 0;
        loadNonceCounter <= 0;
        squeezeCounter <= 0;
    endmethod

    method Action key(Block block) if (state == LoadKey);
        keyStore <= shiftInAtN(keyStore, bytesToWord(block));
        loadKeyCounter <= loadKeyCounter + 1;
        if (loadKeyCounter == 1)
            state <= Absorb;
    endmethod

    method ActionValue#(Block) absorb(Block block, ByteValids valids, Flags flags) if (state == Absorb);
        Block rateBlock = wordsToBytes(take(asconState));
        Block xoredBlock = unpack(pack(block) ^ pack(rateBlock));
        AsconState absorbedState = asconState;
        Block ctBlock = xoredBlock;
        for (Integer i = 0; i < valueOf(BlockBytes); i = i + 1) 
            if (valids[i]) ctBlock[i] = block[i];
        
        // TODO move to flags:
        let emptyAD = flags.ad && flags.first && !valids[0];
        let firstAD = flags.ad && flags.first;
        let lastPtCtHash = flags.last && !flags.npub && !flags.ad;
        let pb = !flags.hash && !flags.npub && !(flags.ptct && flags.last);

        if (!emptyAD)
            absorbedState[0] = bytesToWord(flags.ct ? ctBlock : xoredBlock); // FIXME

        let k = valueOf(KeyWords);
        if (firstAD) begin
            for (Integer i = 0; i < k; i = i + 1)
                absorbedState[5-k+i] = asconState[5-k+i] ^ keyStore[i];
        end else if (flags.ptct) begin
            if (flags.last)
                for (Integer i = 0; i < k; i = i + 1)
                    absorbedState[rateWords + i] = asconState[rateWords + i] ^ keyStore[i];
            if (flags.first)
                absorbedState[4][0] = absorbedState[4][0] ^ 1; // last bit of state
        end

        if (flags.npub) begin
            loadNonceCounter <= loadNonceCounter + 1;
            if (loadNonceCounter == 1) begin
                asconState <= keyNonceInit(block, keyStore);
                state <= Permute;
            end else
                asconState[3] <= bytesToWord(block); // Npub_0
        end else begin
            asconState <= absorbedState;
            if (!emptyAD)
                state <= Permute;
        end
        roundConstant <= initRC(pb);
        roundCounter <= pb ? fromInteger(valueOf(pa_cycles) - valueOf(pb_cycles)) : 0;
        postPermuteState <= lastPtCtHash ? Squeeze : Absorb;
        squeezeHash <= flags.hash;
        return xoredBlock;
    endmethod

    method ActionValue#(BlockOfSize#(8)) squeeze if (state == Squeeze);
        squeezeCounter <= squeezeCounter + 1;
        if (squeezeCounter[0] == 1'b1 && (!squeezeHash || squeezeCounter[1] == 1'b1))
            state <= Idle;
        else if (squeezeHash)
            state <= Permute;

        postPermuteState <= Squeeze;
        roundCounter <= 0;
        roundConstant <= initRC(False); // P_a for hash

        return unpack(
            swapEndian(squeezeHash ? asconState[0] : asconState[squeezeCounter[0] == 1'b1 ? 4 : 3] ^ keyStore[squeezeCounter[0]])
        );
    endmethod
endmodule

endpackage