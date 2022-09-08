from typing import List, Optional, Union

from cocotb.utils import get_sim_time
from .lwc_api import LwcAead, LwcHash

from cocotb.handle import SimHandleBase
from cocotb.triggers import (First, Join, ReadOnly, RisingEdge, Timer)

from .hw_api import Instruction, Segment, SegmentType, OpCode, Status
from .utils import rand_bytes
from .valid_ready_tester import ValidReadyTester, ValidReadyDriver, ValidReadyMonitor


def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]


def show_messages(messages, width):
    num_messages = len(messages)
    digits = width // 4
    for message_idx, words in enumerate(messages):
        lines = [' '.join(l) for l in chunks(
            [f'{word:0{digits}x}' for word in words], 10)]
        preamble = f"[{message_idx+1}/{num_messages}:{len(words)}] "
        preamble = f'{preamble:<12}'
        print(preamble + f'\n{" "*len(preamble)}'.join(lines))


class Tb(ValidReadyTester):
    def __init__(self, dut: SimHandleBase, input_buses: List[str], output_buses: List[str], debug=False, clk_period=10, max_in_stalls=0, max_out_stalls=0, min_out_stalls=0) -> None:
        reset_val = 1
        reset_name = 'rst'
        if hasattr(dut, 'rst_n'):
            print("rst_n port detected. Using active-low reset!")
            reset_val = 0
            reset_name = 'rst_n'
        super().__init__(dut, input_buses, output_buses, debug=debug, clock_name='clk', clk_period=clk_period, reset_name=reset_name,
                         reset_val=reset_val, max_in_stalls=max_in_stalls, max_out_stalls=max_out_stalls, min_out_stalls=min_out_stalls)

    async def launch_monitors(self):
        for mon in self.monitors.__dict__.values():
            await mon.fork()

    async def launch_drivers(self):
        for driver in self.drivers.__dict__.values():
            await driver.fork()

    async def join_monitors(self, timeout=None):
        for mon in self.monitors.__dict__.values():
            await mon.join(timeout)

    async def join_drivers(self, timeout=None):
        for driver in self.drivers.__dict__.values():
            await driver.join(timeout)


class LwcTb(Tb):
    def __init__(self, dut: SimHandleBase, debug=False, max_in_stalls=0, max_out_stalls=0, min_out_stalls=0) -> None:

        super().__init__(dut=dut,
                         input_buses=['pdi', 'sdi'], output_buses=['do'], debug=debug, max_in_stalls=max_in_stalls, max_out_stalls=max_out_stalls, min_out_stalls=min_out_stalls)

        self.pdi: ValidReadyDriver = self.drivers.pdi
        self.sdi: ValidReadyDriver = self.drivers.sdi
        self.do: ValidReadyMonitor = self.monitors.do

    def enqueue_message(self, instruction: Instruction, *segments: Segment):
        sender = self.sdi if instruction.op == OpCode.LDKEY else self.pdi
        width = sender.width

        # self.log.debug(f'enqueuing instruction {instruction} on {sender.name}')
        message = instruction.to_words(width)
        last_idx = len(segments) - 1
        for i, segment in enumerate(segments):
            last = i == last_idx

            segment.header.last = last

            # eoi = last
            # if not last:
            eoi = True
            for x in segments[i+1:]:
                if x.len and x.type not in {SegmentType.TAG, SegmentType.LENGTH}:
                    eoi = False
                    break

            segment.header.last = last
            segment.header.eoi = eoi
            segment.header.eot = last or segments[i+1].type != segment.type

            message.extend(segment.to_words(width))

        sender.queue.put(message)

    def expect_message(self, *segments: Segment, status=Status.Success):
        width = self.do.width
        message = []
        for segment in segments:
            exp_words = segment.to_words(width)
            message.extend(exp_words)
        message.extend(status.to_words(width))
        self.do.queue.put(message)

    async def encrypt_test(self, key, nonce, ad, pt, ct, tag):
        self.enqueue_message(Instruction(OpCode.ACTKEY))
        self.enqueue_message(Instruction(OpCode.LDKEY),
                             *Segment.segmentize(SegmentType.KEY, key))
        self.enqueue_message(Instruction(OpCode.ENC),
                             *Segment.segmentize(SegmentType.NPUB, nonce),
                             *Segment.segmentize(SegmentType.AD, ad),
                             *Segment.segmentize(SegmentType.PT, pt))
        # EOI is set to ‘0’ for output segments
        self.expect_message(
            *Segment.segmentize(SegmentType.CT, ct, last=0, eot=1, eoi=0),
            *Segment.segmentize(SegmentType.TAG, tag, last=1, eot=1, eoi=0)
        )

    async def decrypt_test(self, key, nonce, ad, pt, ct, tag):
        self.enqueue_message(Instruction(OpCode.ACTKEY))
        self.enqueue_message(Instruction(OpCode.LDKEY),
                             *Segment.segmentize(SegmentType.KEY, key))
        self.enqueue_message(Instruction(OpCode.DEC),
                             *Segment.segmentize(SegmentType.NPUB, nonce),
                             *Segment.segmentize(SegmentType.AD, ad),
                             *Segment.segmentize(SegmentType.CT, ct),
                             *Segment.segmentize(SegmentType.TAG, tag)
                             )
        self.expect_message(Segment(SegmentType.PT, pt, last=1, eot=1, eoi=0))

    async def hash_test(self, hm, digest):
        self.enqueue_message(Instruction(OpCode.HASH),
                             *Segment.segmentize(SegmentType.HM, hm)
                             )
        self.expect_message(
            *Segment.segmentize(SegmentType.DIGEST, digest, last=1, eot=1, eoi=0))


class LwcRefCheckerTb(LwcTb):
    def __init__(self, dut: SimHandleBase, ref: Union[LwcAead, LwcHash], debug, max_in_stalls, max_out_stalls, min_out_stalls=None, supports_hash=True) -> None:
        super().__init__(dut, debug=debug, max_in_stalls=max_in_stalls,
                         max_out_stalls=max_out_stalls, min_out_stalls=min_out_stalls)
        self.debug = debug
        self.ref = ref
        self.supports_hash = supports_hash
        self.rand_inputs = not debug

    def gen_inputs(self, numbytes):
        s = 0 if numbytes > 1 else 1
        return rand_bytes(numbytes) if self.rand_inputs else bytes([i % 255 for i in range(s, numbytes+s)])

    async def xenc_test(self, ad_size, pt_size):
        key = self.gen_inputs(self.ref.CRYPTO_KEYBYTES)
        npub = self.gen_inputs(self.ref.CRYPTO_NPUBBYTES)
        ad = self.gen_inputs(ad_size)
        pt = self.gen_inputs(pt_size)
        ct, tag = self.ref.encrypt(pt, ad, npub, key)
        if self.debug:
            print(f'key={key.hex()}\nnpub={npub.hex()}\nad={ad.hex()}\n' +
                  f'pt={pt.hex()}\nct={ct.hex()}\ntag={tag.hex()}\n')
        await self.encrypt_test(key, npub, ad, pt, ct, tag)

    async def xdec_test(self, ad_size, ct_size):
        key = self.gen_inputs(self.ref.CRYPTO_KEYBYTES)
        npub = self.gen_inputs(self.ref.CRYPTO_NPUBBYTES)
        ad = self.gen_inputs(ad_size)
        pt = self.gen_inputs(ct_size)
        ct, tag = self.ref.encrypt(pt, ad, npub, key)
        if self.debug:
            print(f'key={key.hex()}\nnpub={npub.hex()}\nad={ad.hex()}\n' +
                  f'pt={pt.hex()}\n\nct={ct.hex()}\ntag={tag.hex()}')
        await self.decrypt_test(key, npub, ad, pt, ct, tag)

    async def xhash_test(self, hm_size):
        hm = self.gen_inputs(hm_size)
        digest: bytes = self.ref.hash(hm)
        if self.debug:
            print(f'message={hm.hex()}\ndigest={digest.hex()}')
        await self.hash_test(hm, digest=digest)

    async def measure_op(self, op_dict: dict, timeout=None):
        t0 = get_sim_time()
        op = op_dict['op']
        ad_size = op_dict.get('ad_size')
        xt_size = op_dict.get('xt_size')
        hm_size = op_dict.get('hm_size')
        if op == 'enc':
            assert ad_size is not None and xt_size is not None
            await self.xenc_test(ad_size=ad_size, pt_size=xt_size)
        elif op == 'dec':
            assert ad_size is not None and xt_size is not None
            await self.xdec_test(ad_size=ad_size, ct_size=xt_size)
        elif op == 'hash':
            assert hm_size is not None
            await self.xhash_test(hm_size=hm_size)
        await self.launch_monitors()
        await self.launch_drivers()
        await self.join_drivers(timeout)
        await self.join_monitors(timeout)
        t1 = get_sim_time()
        cycles = (t1 - t0) // self.clock_period
        return cycles - 1  # consistent with VHDL TB
