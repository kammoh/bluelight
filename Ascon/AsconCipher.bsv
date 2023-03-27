package AsconCipher;

import Vector :: *;
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

typedef 128 KeyBits;
typedef 128 NonceBits;

typedef TDiv#(KeyBits, 32) NumKeyWords;

interface CipherIfc#(numeric type n_bytes, type flags_type);
    // optional operation-specific initialization
    method Action start (OpFlags op);
    
    // load key into internal key buffer
    method Action loadKey (CoreWord word, Bool last);

    // block in/out
    method ActionValue#(BlockOfSize#(n_bytes)) absorb(BlockOfSize#(n_bytes) block, ByteValidsOfSize#(n_bytes) valids, Bool last, flags_type flags); 
    // block out
    method ActionValue#(BlockOfSize#(8)) squeeze;
endinterface

module mkAsconCipher (CipherIfc#(BlockBytes, HeaderFlags)) provisos (Mul#(UnrollFactor, pa_cycles, PaRounds), Mul#(UnrollFactor, pb_cycles, PbRounds));
    Reg#(AsconState) asconState <- mkRegU;
    let state <- mkReg(Idle);
    Reg#(State) postPermuteState <- mkRegU;

    Reg#(Vector#(NumKeyWords, CoreWord)) keyStore <- mkRegU;
    Reg#(Bit#(TLog#(pa_cycles))) roundCounter <- mkRegU;
    Reg#(RoundConstant) roundConstant <- mkRegU;
    Reg#(Bit#(2)) squeezeCounter <- mkRegU; // 2 bits if supports hash, o/w 1 bit
    Reg#(Bit#(TLog#(TDiv#(NonceBits, TMul#(BlockBytes, 8))))) loadNonceCounter <- mkRegU;
    Reg#(Bool) squeezeHash <- mkRegU;
    Reg#(Bool) first_block <- mkRegU; // first block of a type

    Vector#(2, AsconWord) storedKey = reverse(unpack(pack(reverse(keyStore))));

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
    method Action start (OpFlags op) if (state == Idle);
        if(op.hash) begin
            asconState <= unpack(pack(zeroExtend(getIV(True))));
            roundConstant <= initRC(False);
        end
        state <= op.hash ? Permute : op.new_key ? LoadKey : LoadKey;
        postPermuteState <= Absorb;
        roundCounter <= 0;
        loadNonceCounter <= 0;
        squeezeCounter <= 0;
        first_block <= True;
    endmethod

    method Action loadKey (CoreWord word, Bool last) if (state == LoadKey);
        keyStore <= shiftInAtN(keyStore, swapEndian(pack(word)));
        if (last)
            state <= Absorb;
    endmethod

    method ActionValue#(Block) absorb (Block block, ByteValids valids, Bool last, HeaderFlags flags) if (state == Absorb);
        Block rateBlock = wordsToBytes(take(asconState));
        Block xoredBlock = unpack(pack(block) ^ pack(rateBlock));
        AsconState absorbedState = asconState;
        Block ctBlock = xoredBlock;
        for (Integer i = 0; i < valueOf(BlockBytes); i = i + 1) 
            if (valids[i]) ctBlock[i] = block[i];

        if (last || flags.npub)
            first_block <= True;
        else
            first_block <= False;
        
        // TODO move to flags:
        let emptyAD = flags.ad && first_block && !valids[0];
        let firstAD = flags.ad && first_block;
        let lastPtCtHash = last && !flags.npub && !flags.ad;
        let pb = !flags.hm && !flags.npub && !(flags.ptct && last);

        if (!emptyAD)
            absorbedState[0] = bytesToWord(flags.ct ? ctBlock : xoredBlock); // FIXME

        let k = 2;
        if (firstAD) begin
            for (Integer i = 0; i < k; i = i + 1)
                absorbedState[5-k+i] = asconState[5-k+i] ^ storedKey[i];
        end else if (flags.ptct) begin
            if (last)
                for (Integer i = 0; i < k; i = i + 1)
                    absorbedState[rateWords + i] = asconState[rateWords + i] ^ storedKey[i];
            if (first_block)
                absorbedState[4][0] = absorbedState[4][0] ^ 1; // last bit of state
        end

        if (flags.npub) begin
            loadNonceCounter <= loadNonceCounter + 1;
            if (loadNonceCounter == 1) begin
                asconState <= keyNonceInit(block, storedKey);
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
        squeezeHash <= flags.hm;
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
            swapEndian(squeezeHash ? asconState[0] : asconState[squeezeCounter[0] == 1'b1 ? 4 : 3] ^ storedKey[squeezeCounter[0]])
        );
    endmethod
endmodule

endpackage