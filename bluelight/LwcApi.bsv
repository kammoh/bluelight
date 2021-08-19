package LwcApi;

import FIFO::*;
import FIFOF::*;
import SpecialFIFOs :: * ;
import GetPut :: *;

import Bus :: *;
import CryptoCore :: *;

typedef DataLast#(CoreWord) CoreWordWithLast;

interface LwcIfc;
    interface BusRecv#(CoreWord) pdi;
    interface BusRecv#(CoreWord) sdi;
    (* prefix = "do" *)
    interface BusSendWL#(CoreWord) do_;
endinterface

typedef enum {
    GetPdiInstruction,
    GetPdiHeader,
    GetPdiData,
    GetTagHeader,
    GetTagData,
    EnqTagHeader
} PdiState deriving (Bits, Eq, FShow);

typedef enum {
    SdiIdle,
    SdiInstruction,
    SdiHeader,
    SdiData
} SdiState deriving (Bits, Eq, FShow);

typedef enum {
    SendHeader,
    SendData,
    VerifyTag,
    SendStatus
} OutputState deriving (Bits, Eq, FShow);

typedef enum {
    AD          = 4'b0001,
    Plaintext   = 4'b0100,
    Ciphertext  = 4'b0101,
    Npub        = 4'b1101,
    HashMessage = 4'b0111,
    Key         = 4'b1100,
    Tag         = 4'b1000,
    Digest      = 4'b1001
} SegmentType deriving (Bits, Eq, FShow);

// LSB of LWC instruction
// typedef enum {
//     ACTKEY  = 4'b111, // -> 01
//     ENC     = 4'b010, // -> 10
//     DEC     = 4'b011, // -> 11
//     HASH    = 4'b000  // -> 00
// } OpCode deriving (Bits, Eq, FShow);
// only CoreWord (8, 16, 32 bits) needed for instruction
typedef Bit#(3) OpCode;
function OpCode getOpcode(CoreWord w);
    Bit#(4) op4 = truncateLSB(w);
    return unpack(truncate(op4));
endfunction

function Bool isActKey(OpCode op);
    // thrid bit 1, on pdi, it's ACTKEY! (LDKEY is on sdi only)
    return op[2] == 1'b1;
endfunction

function Bool isHash(OpCode op);
    return op[1] == 1'b0;
endfunction

function Bool isDecIfNotActKey(OpCode op);
    return op[0] == 1'b1;
endfunction


// Segment header
typedef UInt#(32) Header;
function Header make_header(SegmentType t, Bool eot, Bool last, Bit#(16) len) = unpack({pack(t) , 1'b0, 1'b0, pack(eot), pack(last), 8'b0, len});
function SegmentType headerType(Header w) = unpack(pack(w)[31:28]);
function Bit#(16) headerLen(Header w) = pack(w)[15:0];
function Bool headerLast(Header w) = unpack(pack(w)[24]);
function Bool headerEoT(Header w) = unpack(pack(w)[25]);
function Bool headerEoI(Header w) = unpack(pack(w)[26]);

module mkLwc#(CryptoCoreIfc cryptoCore, Bool ccIsLittleEndian, Bool ccPadsOutput) (LwcIfc);
    function Bit#(n) lwcSwapEndian(Bit#(n) word) provisos (Mul#(nbytes, 8, n), Div#(n, 8, nbytes));
        return ccIsLittleEndian ? swapEndian(word) : word;
    endfunction

    // should be synthesized out when ccPadsOutput is True TODO: verify QoR
    function CoreWord lwcPadWord(CoreWord word, Bit#(2) padarg);
        return ccPadsOutput ? word : tpl_2(padWord(word, padarg, 0));
    endfunction


    BusReceiver#(CoreWord) pdiReceiver <- mkPipelineBusReceiver;
    BusReceiver#(CoreWord) sdiReceiver <- mkPipelineBusReceiver;

    let pdiGet = fifoToGet(pdiReceiver.out).get;
    let sdiGet = fifoToGet(sdiReceiver.out).get;

    Reg#(Bit#(14)) pdiCounter                    <- mkRegU;
    Reg#(Bit#(TLog#(CryptoKeyWords))) sdiCounter <- mkRegU;
    Reg#(Bit#(14)) outCounter                    <- mkRegU;
    Reg#(Bit#(2))  finalRemainBytes              <- mkRegU;
    Reg#(Bit#(2))  outRemainder                  <- mkRegU;

    Reg#(Bool) inSegLast   <- mkRegU; // last segment
    Reg#(Bool) outSegLast  <- mkRegU; // last segment
    Reg#(Bool) inSegEoT    <- mkRegU; // last segment of its type
    Reg#(Bool) newKey      <- mkRegU; // should receive and use a new key
    Reg#(Bool) statFailure <- mkReg(False); // status use in output

    Reg#(SegmentType) inSegType   <- mkRegU;
    Reg#(SegmentType) outSegType  <- mkRegU;

    let pdiState <- mkReg(GetPdiInstruction);
    let sdiState <- mkReg(SdiIdle);
    let outState <- mkReg(SendHeader);

    FIFO#(Header) headersFifo <- mkPipelineFIFO;
    FIFO#(CoreWord) tagFifo <- mkPipelineFIFO;

    let doSender <- mkBusSenderWL(?);

    let inWordCounterMsbZero = pdiCounter[13:1] == 0;
    let outCounterMsbZero = outCounter[13:1] == 0;

    let last_of_seg = inWordCounterMsbZero && ((pdiCounter[0] == 0) || (finalRemainBytes == 0));

//===================================================== Rules =========================================================

//------------------------------------------------------ SDI ----------------------------------------------------------
    (* fire_when_enabled *)
    rule get_sdi_inst if (sdiState == SdiInstruction && pdiState != GetPdiInstruction);
        let w <- sdiGet;
        sdiState <= SdiHeader;
    endrule

    (* fire_when_enabled *)
    rule get_sdi_hdr if (sdiState == SdiHeader && pdiState != GetPdiInstruction);
        let w <- sdiGet;
        sdiCounter       <= fromInteger(valueof(CryptoKeyWords) - 1);
        sdiState <= SdiData;
    endrule

    (* fire_when_enabled *)
    rule feed_core_sdi if (sdiState == SdiData && pdiState != GetPdiInstruction);
        let w <- sdiGet;
`ifdef LWC_DEBUG
        $displayh("rl_feed_core_sdi: key word: ", w);
`endif
        sdiCounter <= sdiCounter - 1;
        let last = sdiCounter == 0;

        cryptoCore.key (lwcSwapEndian(w), last); // 0 -> no padding 1 -> 3, 2-> 2, 3-> 1

        if (last) sdiState <= SdiIdle;
    endrule

//------------------------------------------------------ PDI ----------------------------------------------------------
    (* fire_when_enabled *)
    rule pdi_instruction if (pdiState == GetPdiInstruction);
        let w <- pdiGet;
        let op_code = getOpcode(w);
        if (isActKey(op_code)) begin
            sdiState <= SdiInstruction;
            newKey <= True;
        end else begin
            pdiState <= GetPdiHeader;
            cryptoCore.init (newKey, isDecIfNotActKey(op_code), isHash(op_code));
            newKey <= False; // reset for next init
        end
    endrule

    (* fire_when_enabled *)
    rule get_pdi_hdr if (pdiState == GetPdiHeader);
        let w <- pdiGet;
        Header hdr = unpack(w);
        let typ  = headerType(hdr);
        let len  = headerLen(hdr);
        let last = headerLast(hdr);
        let eot  = headerEoT(hdr);

        inSegType <= typ;
        inSegEoT  <= eot;
`ifdef LWC_DEBUG
        $display("Got header: typ: ", fshow(typ), ", len: ", len, " eot:", eot, " last:", last);
`endif

        pdiCounter    <= len[15:2];
        finalRemainBytes <= len[1:0]; 
        inSegLast        <= last;

        let empty = len == 0;

        let isPtCt = pack(typ)[3:1] == 3'b010;
        let isPt   = pack(typ)[0] == 1'b0;
        let isNpub = pack(typ)[3] == 1'b1;
        let isAD   = pack(typ)[2] == 1'b0;
        let isHM   = pack(typ)[1] == 1'b1;
        let isCt   = isPtCt && !isPt;

        if(isPtCt)
            headersFifo.enq(make_header(isPt ? Ciphertext : Plaintext, eot,  !isPt, len));
        else if (isHM && last) // mutually exclusive but scheduler doesn't know about the encoding, therefore need else
            headersFifo.enq(make_header(Digest, True, True, fromInteger(crypto_hash_bytes)));

        cryptoCore.anticipate (isNpub, isAD, isPt, isCt, empty, headerEoI(hdr));

        if (empty) begin
            if(eot && isCt)
                pdiState <= GetTagHeader;
            else if (last)
                pdiState <= isPt ? EnqTagHeader : GetPdiInstruction;
            // otherwise: get more PDI headers
        end else
            pdiState <= GetPdiData;
    endrule

    (* fire_when_enabled *)
    rule feed_core_pdi if (pdiState == GetPdiData);
        let w <- pdiGet;
`ifdef LWC_DEBUG
        $displayh("rl_feed_core: got w=", w);
`endif
        pdiCounter <= pdiCounter - 1;

        let last = last_of_seg && inSegEoT;

        cryptoCore.bdi( BdIO {word: lwcSwapEndian(w), last: last, padarg: finalRemainBytes} ); // 0 -> no padding 1 -> 3, 2-> 2, 3-> 1

        if (last_of_seg) begin
            if (inSegEoT && inSegType == Plaintext)
                pdiState <= EnqTagHeader;
            else if (inSegEoT && inSegType == Ciphertext)
                pdiState <= GetTagHeader;
            else
                pdiState <= inSegLast ? GetPdiInstruction : GetPdiHeader;
        end
        endrule

        (* fire_when_enabled *)
        rule get_tag_hdr if (pdiState == GetTagHeader);
        let w      <- pdiGet;
        Header hdr = unpack(w);
        let len    = headerLen(hdr);

        pdiCounter <= len[15:2];

        pdiState <= GetTagData;
`ifdef LWC_DEBUG
    $display("GetTagHeader Got header: ", ", len: ", len);
`endif
    endrule

    (* fire_when_enabled *)
    rule get_tag_data if (pdiState == GetTagData);
        let w <- pdiGet;
`ifdef LWC_DEBUG
        $displayh("rl_feed_core: got w=", w);
`endif
        pdiCounter <= pdiCounter - 1;
        tagFifo.enq(w);

        if (inWordCounterMsbZero)
            pdiState <= GetPdiInstruction;
        endrule

    (* fire_when_enabled *)
    rule enq_tag if (pdiState == EnqTagHeader); // only in encrypt, after last Plaintext was read
        headersFifo.enq(make_header(Tag, True, True, fromInteger(crypto_abytes)));
        pdiState <= GetPdiInstruction;
    endrule

    /// output ///
    (* fire_when_enabled *) // ???
    rule out_header if (outState == SendHeader);
        headersFifo.deq;
        let h = headersFifo.first;
        let len = headerLen(h);
        let typ = headerType(h);
        let eot = headerEoT(h);
        let last = headerLast(h);
        doSender.in.enq(CoreWordWithLast { data: pack(h), last: False } );

        outSegType <= typ;
        outSegLast <= last;

        match {.hi, .lo} = split(len);
        outRemainder <= lo;

        if (len != 0) begin
            outCounter <= hi;
            outState   <= SendData;
        end
        else if (typ == Plaintext) begin
            outState  <= VerifyTag;
            outCounter <= 4; //FIXME from core/inputs
        end
        else if (last)
            outState <= SendStatus;
    endrule

    (* fire_when_enabled *)
    rule verify_tag if (outState == VerifyTag);
        tagFifo.deq;
        cryptoCore.bdo.deq;
        let intag = tagFifo.first;
        outCounter <= outCounter - 1;

        let sw = lwcSwapEndian(cryptoCore.bdo.first.word);

`ifdef LWC_DEBUG
        $display("Verifytag got tag:%h core:%h", intag, sw);
`endif

        if (intag != sw) begin
`ifdef LWC_DEBUG
            $displayh("Tag mismatch: %h != %h ", intag, sw);
`endif
            statFailure <= True;
        end

        if (outCounterMsbZero)
            outState <= SendStatus;
    endrule

    (* fire_when_enabled *)
    rule sendout_data if (outState == SendData);
        cryptoCore.bdo.deq;
        let word = cryptoCore.bdo.first.word;
        let padarg = cryptoCore.bdo.first.padarg;
        let last = cryptoCore.bdo.first.last;
        let pw = lwcPadWord(word, padarg);
        doSender.in.enq(CoreWordWithLast { data: lwcSwapEndian(last ? pw : word), last: False} );
        if (outCounterMsbZero && ((outCounter[0] == 0) || (outRemainder == 0))) begin
            if (outSegLast)
                if (outSegType == Plaintext) begin
                    outCounter <= 4;
                    outState <= VerifyTag;
                end else 
                    outState <= SendStatus;
            else
                outState <= SendHeader; // more headers
        end else
            outCounter <= outCounter - 1;
    endrule

    (* fire_when_enabled *)
    rule out_status if (outState == SendStatus);
        doSender.in.enq(CoreWordWithLast { data: {3'b111, pack(statFailure), 28'b0}, last: True });
        statFailure <= False;
        outState <= SendHeader;
    endrule

    interface pdi = pdiReceiver.in;
    interface sdi = sdiReceiver.in;
    interface do_ = doSender.out;
  
endmodule

endpackage : LwcApi