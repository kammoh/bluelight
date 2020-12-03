#!/usr/bin/env python3
from cocotb_test.simulator import Icarus, Verilator

from pathlib import Path
import subprocess
import sys

lib_paths = []

lib_paths.insert(0, '+')

bsc_flags = ['-aggressive-conditions', '-steps-warn-interval', '2000000', '-remove-unused-modules',
             '-steps-max-intervals', '6000000', '-opt-undetermined-vals', '-unspecified-to', 'X',
             '-show-compiles', '-show-module-use']

# bsc_flags = ['-keep-fires', '-keep-inlined-boundaries']


bsc_out_path = Path.cwd() / 'bsc_out'


def make_verilog(top_file, toplevel):
    bsc_out_path.mkdir(exist_ok=True)
    bsc_out = str(bsc_out_path)
    try:
        subprocess.run(['bsc'] + bsc_flags + ['-bdir', bsc_out, '-info-dir', bsc_out, '-sat-yices',
                                            '-u', '-verilog',
                                            '-p', ':'.join(lib_paths),
                                            '-D', 'BSV_POSITIVE_RESET',
                                            '-remove-unused-modules',
                                            '-vdir', bsc_out, '-g', toplevel, top_file], check=True)
    except Exception as e:
        print(f"bsc failed with return code: {e.args[0]}")
        sys.exit(1)
    # subprocess.run(['bsc'] + ['-bdir', bsc_out, '-vdir', bsc_out, '-verilog',
    #                           '-D', 'BSV_POSITIVE_RESET',
    #                           '-remove-unused-modules', '-e', toplevel], check=True)


def test_xoodoo():
    top = 'mkXoodyakLWC'
    make_verilog('XoodyakLWC.bsv', top)
    verilog_sources = list(bsc_out_path.glob('*.v'))
    sim = Verilator(extra_args=['--trace', '--trace-structs', '-Wno-STMTDLY', '-Wno-INITIALDLY', f'-I/usr/local/opt/bluespec/lib/Verilog'],
                    verilog_sources=verilog_sources,
                    toplevel=top,
                    module="xoodyakTb"
                    )
    # sim = Icarus(verilog_sources=bsc_out_path.glob('*.v'),
    #                 toplevel=top,
    #                 module="xoodyakTb"
    #                 )

    sim.run()


if __name__ == "__main__":
    test_xoodoo()
