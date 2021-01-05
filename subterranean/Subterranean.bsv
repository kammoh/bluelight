// ====================================================================================================================
// Subterranean 2.0 LWC
// Copyright © 2021 Kamyar Mohajerani. All Rights Reserved.
// ====================================================================================================================

package Subterranean;

import Vector :: *;
import List :: *;
import FIFO :: *;
import FIFOF :: *;
import SpecialFIFOs :: *;

import CryptoCore :: *;
import SubterraneanDefs :: *;

// ====================================================================================================================

typedef enum {
    Idle, Absorb, Blank, Squeeze
} State deriving(Bits, Eq, FShow);

// ====================================================================================================================

function Action dumpState(String msg, Bit#(257) state);
  action
    $write("%s  %d ", msg, state[256]);
    for(Integer i = 255; i > 0; i = i - 32) begin
        Bit#(32) x = state[i: i - 31];
        $write("%08x", x, i > 32 ? " " : "\n");
    end
  endaction
endfunction

function Substate addWord(Substate s, Bit#(33) w);
    Substate r = s;
    Integer i;
    for(i=0; i<33; i=i+1)
        r[multiplicativeSubgroup[i]] = s[multiplicativeSubgroup[i]] ^ w[i];
    return r;
endfunction

function Bit#(32) extractWord(Substate s);
    Bit#(32) r;
    let m = valueOf(SubterraneanSize);
    Integer i;
    for(i=0; i<32; i=i+1) begin
        let j = multiplicativeSubgroup[i];
        r[i] = s[j] ^ s[m - j];
    end
    return r;
endfunction

// ====================================================================================================================

(* synthesize *)
module mkSubterranean(CryptoCoreIfc);
    
    // ================================================== Instances ===================================================
    
    FIFOF#(BdIO) outFIFO <- mkDFIFOF(?);
    Reg#(Substate) substate <- mkRegU;
    let state <- mkReg(Idle);
    Reg#(State) retState <- mkRegU;
    Reg#(Bool) decrypt <- mkRegU;
    Reg#(Bool) hash <- mkRegU;
    Reg#(Bool) needsBlank8  <- mkRegU;
    Reg#(Bool) extractWhileAbsorb <- mkRegU;
    Reg#(Bit#(TLog#(9))) blankCounter <- mkRegU;
    Reg#(Bool) last <- mkDWire(False);
    Reg#(Bit#(2)) padding <- mkDWire(0);
    Reg#(Bit #(33)) rwDuplex <- mkWire;
    let initSubstate <- mkPulseWire;
    let extract <- mkPulseWireOR;
    let sqz <- mkPulseWire;
    let dec <- mkPulseWire;

    // ==================================================== Rules =====================================================

    (* fire_when_enabled *)
    rule rl_duplex if (!initSubstate);
        $writeh ("duplex w=", rwDuplex);
        dumpState(" | before round:", substate);

        let w = {rwDuplex[31:1], sqz ? 0 : rwDuplex[0]};
        let xw = extractWord(substate);
        match {.padded, .pw} = padWord( xw, padding, False);
        let outWord = (last ? pw : xw) ^ w;
        substate <= addWord(round(substate), dec ? {pack (!last || !padded), outWord} : rwDuplex);
        if (extract) begin
            outFIFO.enq(BdIO {word: outWord, lot: last, padarg: padding});
        end
    endrule

    (* fire_when_enabled *)
    rule rl_blank_squeeze if (state == Blank || (state == Squeeze && outFIFO.notFull));
        rwDuplex <= 1;
        if (blankCounter == 0) begin
            retState <= Idle;
            state <= retState;
            if (retState == Squeeze) begin
                blankCounter <= 3;
            end
        end else
            blankCounter <= blankCounter - 1;
            
        if(state == Squeeze) begin
            sqz.send();
            extract.send();
        end
    endrule

    (* fire_when_enabled *)
    rule rl_init_substate if (initSubstate);
        substate <= 0;
    endrule

    // ================================================== Interfaces ==================================================

    method Action process(SegmentType typ, Bool empty) if (state == Idle && (outFIFO.notFull));
    
        let typeIsCT       = typ == Ciphertext;
        let typeIsPTorCT   = typ == Plaintext || typeIsCT;
        let typeIsHM       = typ == HashMessage;
        let needingBlank8  = typeIsPTorCT || typeIsHM || typ == Npub;
        let needingSqueeze = typeIsPTorCT || typeIsHM;

        decrypt <= typeIsCT;
        hash    <= typeIsHM;
        needsBlank8  <= needingBlank8;
        extractWhileAbsorb <= typeIsPTorCT;

        if (typ == Key || typeIsHM)
            initSubstate.send;

        if (empty)
            rwDuplex <= 1;
        
        blankCounter <= needingBlank8 ? 7 : 0;
        retState <= needingSqueeze ? Squeeze : Idle;
        state <= empty ? (needingBlank8 ? Blank : Idle) : Absorb;
    endmethod

    interface FifoIn bdi;
        method Action enq(i) if (state == Absorb && (!extractWhileAbsorb || outFIFO.notFull));
            match tagged BdIO {word: .word, lot: .lot, padarg: .padarg} = i;
            match {.padded, .pw} = padWord(word, padarg, True); 
            rwDuplex <= {pack (!lot || !padded), lot ? pw : word};
            last <= lot;
            padding <= padarg;

            if (extractWhileAbsorb)
                extract.send();
                
            if (decrypt)
                dec.send();
            
            if (lot) begin
                if (needsBlank8) begin
                    blankCounter <= padded ? 7 : 8; // Npub is always word-aligned, but anyways
                    state <= Blank;
                end
                else
                    state <= padded ? Idle : Blank;
            end
            
        endmethod 
    endinterface

    interface FifoOut bdo = fifofToFifoOut(outFIFO);

endmodule

endpackage