package AsconCipher;

import Vector :: *;
import Printf :: * ;

import BluelightUtils :: *;
import CryptoCore :: *;
import AsconRound :: *;
import LwcApi :: *;

function Action dump_state(String msg, AsconState s);
    action
        $write("%24.24s: ", msg);
        for (Integer i = 0; i < 5; i = i + 1)
            $write(" x%1.1d=%h", i, s[i]);
        $display("");
    endaction
endfunction

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
    method ActionValue#(BlockOfSize#(n_bytes)) absorb (BlockOfSize#(n_bytes) block, ByteValidsOfSize#(n_bytes) valids, Bool last, flags_type flags); 
    // block out
    method ActionValue#(BlockOfSize#(8)) squeeze;
endinterface

typedef struct {
    Bool npub;         // nonce public
    Bool ad;           // associated data
    Bool emptyAD;      // empty associated data
    Bool ct;           // ciphertext
    Bool ptct;         // PT or CT
    Bool hm;           // hash message
    Bool ptCtHm;       // PT or CT or HM
    Bool ptCtAd;       // PT or CT or AD
} Flags deriving(Bits, Eq, FShow);

module mkAsconCipher #(parameter Bool ascon128a) (CipherIfc#(BlockBytes, Flags)) provisos (Mul#(UnrollFactor, pa_cycles, PaRounds), Mul#(UnrollFactor, pb_cycles, PbRounds));
    messageM(sprintf("\n\n*** Ascon-%s UnrollFactor=%d PaRounds=%d PbRounds=%d ***\n\n", ascon128a ? "128A" : "128", valueOf(UnrollFactor), valueOf(PaRounds), valueOf(PbRounds)));
    Reg#(AsconState) asconState <- mkRegU;
    let state <- mkReg(Idle);
    let postPermuteState <- mkReg(Absorb);

    Reg#(Vector#(NumKeyWords, CoreWord)) keyStore <- mkRegU;
    Reg#(Bit#(TLog#(pa_cycles))) roundCounter <- mkReg(0);
    Reg#(RoundConstant) roundConstant <- mkReg(0);
    Reg#(Bit#(2)) squeezeCounter <- mkReg(0); // 2 bits if supports hash, o/w 1 bit
    // Reg#(Bit#(TLog#(TDiv#(NonceBits,TMul#(BlockBytes, 8))))) loadNonceCounter <- mkReg(0);
    Reg#(Bit#(2)) loadNonceCounter <- mkReg(0);
    Reg#(Bool) squeezeHash <- mkReg(False);
    Reg#(Bool) first_block <- mkReg(False); // first block of a type

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
        if (ascon128a) begin
            s[3] = npub[0];
            s[4] = npub[1];
        end else begin
            for (Integer i = 0; i < rateWords; i = i + 1)
                s[4] = npub[0];
        end
        return s;
    endfunction

    // Must be called before any operation
    method Action start (OpFlags op) if (state == Idle);
        if(op.hash) begin
            asconState <= unpack(pack(zeroExtend(getIV(True))));
            roundConstant <= initRC(False);
        end
        state <= op.hash ? Permute : op.new_key ? LoadKey : Absorb;
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

    method ActionValue#(Block) absorb (Block block, ByteValids valids, Bool last, Flags flags) if (state == Absorb);
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
        let firstAD = flags.ad && first_block;
        let firstPtCt = flags.ptct && first_block;
        let lastPtCt = flags.ptct && last;
        let lastPtCtHash = last && flags.ptCtHm;
        let pb = flags.ptCtAd && !(flags.ptct && last);

        if (!flags.emptyAD)
            for (Integer i = 0; i < rateWords; i = i + 1)
                absorbedState[i] = bytesToWord(flags.ct ? takeAt(i*8, ctBlock) : takeAt(i*8, xoredBlock)); // FIXME

        if (lastPtCt) begin
            for (Integer i = 0; i < 2; i = i + 1)
                absorbedState[rateWords + i] = asconState[rateWords + i] ^ storedKey[i];
        end

        if (firstAD) begin
            for (Integer i = 0; i < 2; i = i + 1)
                absorbedState[3+i] = asconState[3+i] ^ storedKey[i];
        end

        absorbedState[4][0] = absorbedState[4][0] ^ pack(firstPtCt); // last bit of state

        if (flags.npub) begin
            if (ascon128a) begin
                asconState <= keyNonceInit(block, storedKey);
                state <= Permute;
            end else begin
                loadNonceCounter <= loadNonceCounter + 1;
                if (loadNonceCounter == 1) begin
                    asconState <= keyNonceInit(block, storedKey);
                    state <= Permute;
                end else
                    asconState[3] <= bytesToWord(take(block)); // Npub_0
            end
        end else begin
            asconState <= absorbedState;
            if (!flags.emptyAD)
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