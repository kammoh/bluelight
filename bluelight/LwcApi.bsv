package LwcApi;

/*--------------------------------- Imports ---------------------------------*/
import FIFO         :: *;
import SpecialFIFOs :: *;
import OInt         :: *;

import Bus           :: *;
import CryptoCore    :: *;
import LwcApiDefines :: *;

/*--------------------------------- Exports ---------------------------------*/
export LwcApiDefines :: *;
export LwcApi        :: *;

/*---------------------------------- Types ----------------------------------*/
typedef enum {
    Pdi_GetInstruction,
    Pdi_Header,
    Pdi_Data,
    Pdi_GetTagHeader,
    Pdi_GetTagData,
    Pdi_SendEmpty,
    // Separate state as we need to send 2 headers when encrypting an empty message:
    Pdi_EnqTagHeader
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

// Segment header
typedef Bit#(32) Header;

function Bit#(4) getHeaderFlags(Bit#(w__) w) provisos (Add#(something__, 8, w__));
    Bit#(8) msb8 = truncateLSB(w);
    return truncate(msb8);
endfunction

function Header makeHeader(SegmentType t, Bool eot, Bool last, SegmentLength len) = 
    unpack({pack(t) , 1'b0, 1'b0, pack(eot), pack(last), 8'b0, pack(len)});

function SegmentLength headerLen(Bit#(w__) w) provisos (Add#(something__, 16, w__));
    return unpack(truncate(w));
endfunction

function Bool headerLast(Header w) = unpack(pack(w)[24]);
function Bool headerEoT(Header w) = unpack(pack(w)[25]);
function Bool headerEoI(Header w) = unpack(pack(w)[26]);

function SegmentType headerType(Header w) = unpack(pack(w)[31:28]);
function Bool isPlaintext(SegmentType typ) = pack(typ)[0] == 1'b0 && pack(typ)[3] == 1'b0;
function Bool isPubNonce(SegmentType typ) = pack(typ)[3] == 1'b1;
function Bool isAssocData(SegmentType typ) = pack(typ)[2] == 1'b0;
function Bool isHashMsg(SegmentType typ) = pack(typ)[1] == 1'b1;
function Bool isText(SegmentType typ) = pack(typ)[3:1] == 3'b010;
function Bool isLength(SegmentType typ) = pack(typ) == 4'b1010;
function Bool isCiphertext(SegmentType typ) = isText(typ) && !isPlaintext(typ);

function Tuple2#(Bit#(a__), Bit#(a__)) toValidBytes(Bit#(b__) last_num_bytes, Bool last, Bool empty) provisos(Add#(c__, 1, a__), Log#(a__, b__));
    Bit#(a__) oh = pack(toOInt(last_num_bytes));
    return (!last || last_num_bytes == 0) ? tuple2(signExtend(1'b1), 0) : empty ? tuple2(0, 1) : tuple2(oh - 1, oh);
endfunction


/*---------------------------------- mkLwc ----------------------------------*/
(* default_clock_osc = "clk" *)
(* default_reset = "rst" *)
module mkLwc#(CryptoCoreIfc#(w__) cryptoCore, Bool ccIsLittleEndian, 
        Integer crypto_key_bytes, Integer crypto_abytes, Integer crypto_hash_bytes) (LwcIfc#(w__)) provisos (Bits#(Bit#(w__), 32), Alias#(t_word, Bit#(w__)));

    function Bit#(n) lwcSwapEndian(Bit#(n) word)
            provisos (Mul#(nbytes, 8, n), Div#(n, 8, nbytes)) = ccIsLittleEndian ? swapEndian(word) : word;

    let pdiReceiver <- mkBusReceiver;
    let sdiReceiver <- mkBusReceiver;
    let doSender    <- mkBusSender;

    Reg#(Bit#(14))    pdiCounter       <- mkReg(0);
    Reg#(Bit#(14))    outCounter       <- mkReg(0);
    Reg#(Bit#(4))     sdiCounter       <- mkReg(0);
    Reg#(Bit#(2))     finalRemainBytes <- mkReg(0);
    Reg#(Bit#(2))     outRemainder     <- mkReg(0);
    Reg#(Bool)        newKey           <- mkReg(False); // should receive and use a new key
    Reg#(Bool)        statFailure      <- mkReg(False); // status use in output
    Reg#(HeaderFlags) inFlags          <- mkReg(HeaderFlags{});
    Reg#(Bool)        inSegLast        <- mkReg(False);
    Reg#(Bool)        inSegEoT         <- mkReg(False);
    Reg#(Bool)        outSegPt         <- mkReg(False);
    Reg#(Bool)        outSegLast       <- mkReg(False);
    Reg#(Bool)        op_decrypt       <- mkReg(False);
    Reg#(Bool)        op_encrypt       <- mkReg(False);

    let pdiState <- mkReg(Pdi_GetInstruction);
    let sdiState <- mkReg(SdiIdle);

    FIFO#(Header) headersFifo <- mkPipelineFIFO;
    FIFO#(t_word) tagFifo     <- mkPipelineFIFO;

    let outState <- mkReg(SendHeader);

    let inWordCounterMsbZero = pdiCounter[13:1] == 0;
    let outCounterMsbZero = outCounter[13:1] == 0;
    let last_of_seg = inWordCounterMsbZero && ((pdiCounter[0] == 0) || (finalRemainBytes == 0));
    let last_word = last_of_seg && inSegEoT;

//===================================================== Rules =========================================================
//---------------------------------------------- SDI ----------------------------------------------
    (* fire_when_enabled *)
    rule get_sdi_inst if (sdiState == SdiInstruction && pdiState != Pdi_GetInstruction);
        let w <- sdiReceiver.get;
        sdiState <= SdiHeader;
    endrule

    (* fire_when_enabled *)
    rule get_sdi_header if (sdiState == SdiHeader && pdiState != Pdi_GetInstruction);
        let w <- sdiReceiver.get;
        sdiCounter <= fromInteger(crypto_key_bytes/(valueof(w__)/8) - 1);
        sdiState <= SdiData;
    endrule

    (* fire_when_enabled *)
    rule get_key_data if (sdiState == SdiData && pdiState != Pdi_GetInstruction);
        let w <- sdiReceiver.get;
        let last = sdiCounter == 0;

        sdiCounter <= sdiCounter - 1;
        cryptoCore.loadKey (lwcSwapEndian(w), last); // 0 -> no padding 1 -> 3, 2-> 2, 3-> 1

        if (last)
            sdiState <= SdiIdle;
    endrule

//---------------------------------------------- PDI ----------------------------------------------
    (* fire_when_enabled *)
    rule pdi_instruction if (pdiState == Pdi_GetInstruction);
        let w <- pdiReceiver.get;
        let op_code = getOpcode(w);

        // (* split *)
        if (opIsActKey(op_code))
            begin
                sdiState <= SdiInstruction;
                newKey <= True;
                op_decrypt <= False;
                op_encrypt <= False;
            end
        else
            begin
                pdiState <= Pdi_Header;
                let decrypt = opIsDecIfNotActKey(op_code);
                let encrypt = opIsEnc(op_code);
                let hash = opIsHash(op_code);
                op_decrypt <= decrypt;
                op_encrypt <= encrypt;
                cryptoCore.start (OpFlags {new_key: newKey, decrypt: decrypt, hash: hash});
                newKey <= False; // reset for next operation
            end
    endrule

    (* fire_when_enabled *)
    rule get_pdi_header if (pdiState == Pdi_Header);
        let pdi_header <- pdiReceiver.get;

        Header hdr = unpack(pdi_header);
        let typ  = headerType(hdr);
        let len  = headerLen(hdr);
        let eoi  = headerEoI(hdr);
        let last = headerLast(hdr);
        let eot  = headerEoT(hdr);

        pdiCounter <= len[15:2];
        finalRemainBytes <= len[1:0]; 
        inSegLast <= last;
        inSegEoT <= eot;

        let empty = len == 0;

        let isPt   = isPlaintext(typ);
        let isAD   = isAssocData(typ);
        let isHM   = isHashMsg(typ);
        let isPtCt = isText(typ);
        let isCt   = isCiphertext(typ);
        

        let flags = HeaderFlags {
            npub:         isPubNonce(typ),
            length:       isLength(typ),
            ad:           isAD,
            pt:           isPt,
            ct:           isCt,
            ptct:         isPtCt,
            hm:           isHM,
            empty:        empty,
            end_of_input: last || (eot && isCt)
        };
        inFlags <= flags;

        if (isPtCt)
            headersFifo.enq(makeHeader(op_decrypt ? Plaintext : Ciphertext, eot, op_decrypt, len));
        else if (eot && isHM)
            headersFifo.enq(makeHeader(Digest, True, True, fromInteger(crypto_hash_bytes)));

        pdiState <= empty ? Pdi_SendEmpty : Pdi_Data;
    endrule

    (* fire_when_enabled *)
    rule send_empty_input if (pdiState == Pdi_SendEmpty);
        cryptoCore.loadData (0, 0, 1, True, inFlags);

        if (inFlags.pt) // send tag
            pdiState <= Pdi_EnqTagHeader;
        else if (inFlags.ct) // verify tag
            pdiState <= Pdi_GetTagHeader;
        else if (inSegLast)
            pdiState <= Pdi_GetInstruction;
        else
            pdiState <= Pdi_Header;
    endrule

    (* fire_when_enabled *)
    rule get_pdi_data if (pdiState == Pdi_Data);
        let pdi_data <- pdiReceiver.get;
        let {vb, pad_loc} = toValidBytes(finalRemainBytes, last_word, False);
        pdiCounter <= pdiCounter - 1;
        cryptoCore.loadData (lwcSwapEndian(pdi_data), vb, pad_loc, last_word, inFlags);

        if (last_of_seg) 
            if (inSegEoT)
                begin
                    if (inFlags.pt) // send tag
                        pdiState <= Pdi_EnqTagHeader;
                    else if (inFlags.ct) // verify tag
                        pdiState <= Pdi_GetTagHeader;
                    else if (inSegLast)
                        pdiState <= Pdi_GetInstruction;
                    else
                        pdiState <= Pdi_Header;
                end
            else
                pdiState <= Pdi_Header;
    endrule

//-------------------------------------------- Tag ------------------------------------------------

    (* fire_when_enabled *)
    rule get_tag_header if (pdiState == Pdi_GetTagHeader);
        let tag_header <- pdiReceiver.get;
        Header hdr = unpack(tag_header);
        let len = headerLen(hdr);

        pdiCounter <= len[15:2];
        pdiState <= Pdi_GetTagData;
    endrule

    (* fire_when_enabled *)
    rule get_tag_data if (pdiState == Pdi_GetTagData);
        let w <- pdiReceiver.get;
        pdiCounter <= pdiCounter - 1;
        tagFifo.enq(w);

        if (inWordCounterMsbZero)
            pdiState <= Pdi_GetInstruction;
    endrule

    (* fire_when_enabled *)
    rule enq_tag if (pdiState == Pdi_EnqTagHeader); // only in encrypt, after last Plaintext was read
        headersFifo.enq(makeHeader(Tag, True, True, fromInteger(crypto_abytes)));
        pdiState <= Pdi_GetInstruction;
    endrule

//------------------------------------------ Output -----------------------------------------------
    (* fire_when_enabled *) // ???
    rule out_header if (outState == SendHeader);
        headersFifo.deq;
        let h = headersFifo.first;
        let len = headerLen(h);
        let typ = headerType(h);
        let eot = headerEoT(h);
        let last = headerLast(h);
        doSender.put (WithLast { data: pack(h), last: False });

        outSegPt <= isPlaintext(typ);
        outSegLast <= last;

        match {.hi, .lo} = split(len);
        outRemainder <= lo;

        if (len != 0)
            begin
                outCounter <= hi;
                outState <= SendData;
            end
        else if (isPlaintext(typ))
            begin
                outCounter <= fromInteger(crypto_abytes * 8 / valueOf(w__));
                outState <= VerifyTag;
            end
        else if (last)
            outState <= SendStatus;

        statFailure <= False;
    endrule


    (* fire_when_enabled *)
    rule verify_tag if (outState == VerifyTag);
        let intag = tagFifo.first;
        let sw = lwcSwapEndian(cryptoCore.data_out.first.data);

        tagFifo.deq;
        cryptoCore.data_out.deq;
        outCounter <= outCounter - 1;

        if (intag != sw)
            statFailure <= True;
        if (outCounterMsbZero)
            outState <= SendStatus;
    endrule


    (* fire_when_enabled *)
    rule sendout_data if (outState == SendData);
        cryptoCore.data_out.deq;
        let word = cryptoCore.data_out.first.data;
        doSender.put ( WithLast { data: lwcSwapEndian(word), last: False} );
        if (outCounterMsbZero && ((outCounter[0] == 0) || (outRemainder == 0))) begin
            if (outSegLast)
                if (outSegPt) begin
                    outCounter <= fromInteger(crypto_abytes * 8 / valueOf(w__));
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
        doSender.put ( WithLast { data: {3'b111, pack(statFailure), 28'b0}, last: True });
        outState <= SendHeader;
    endrule

    interface pdi = pdiReceiver.in;
    interface sdi = sdiReceiver.in;
    
    interface LwcDataOut do_;
        method data = doSender.out.data.data;
        method last = doSender.out.data.last;
        method valid = doSender.out.valid;
        method ready = doSender.out.ready;
    endinterface
  
endmodule

endpackage : LwcApi
