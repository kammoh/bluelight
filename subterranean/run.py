#!/usr/bin/env python3
from math import ceil, log2
from cocotb_test.simulator import Verilator

from pathlib import Path
import subprocess
import sys
import os
import re
import shutil
import argparse

import toml

parser = argparse.ArgumentParser()
parser.add_argument('design')
parser.add_argument('--gen', action='store_true')
parser.add_argument('--debug', action='store_true', default=False)
parser.add_argument('--gtkwave', action='store_true')
parser.add_argument('--seed', default='123', help='random seed (passed to cocotb)')
parser.add_argument('--tests', nargs='+', help='Test functions to run')

args = parser.parse_args()

with open('xedaproject.toml') as f:
    xp = toml.load(f)
designs = xp['design']
if not isinstance(designs, list):
    designs = [designs]
xeda_design = next(
    filter(lambda d: d['name'] == args.design, designs), None)
rtl_settings = xeda_design['rtl']
bluespec_sources = [f for f in rtl_settings['sources']
                    if f.endswith('.bsv') or f.endswith('.bs')]

if args.gtkwave:
    import vcd
    import vcd.gtkw

    def tr_enum(fmt, *symbols):
        sz = ceil(log2(len(symbols)))
        if fmt == 'hex':
            sz = ceil(sz / 4)
        if fmt == 'dec':
            sz = None

        return fmt, sz, [(val, sym) for val, sym in enumerate(symbols)]

    typedef_enum_re = re.compile(
        r'\s*typedef\s+enum\s+{\s*([^}]+)\s*}\s*(\w+)\s*', re.MULTILINE | re.DOTALL)

    def val_to_int(v):
        if isinstance(v, int):
            return ceil(log2(v+1)), v
        m = re.match(r"(\d+)'(b|d|h|o)(\d+)", v)
        if m:
            sz = int(m.group(1))
            base_char = m.group(2)
            base = 10 if base_char == 'd' else 2 if base_char == 'b' else 16 if base_char == 'h' else 8
            return sz, int(m.group(3), base)
        return None, int(v)

    translations = {}

    for bluespec_file in bluespec_sources:
        with open(bluespec_file) as f:
            content = f.read()

            pkg_groups = next(re.finditer(r'\bpackage\s+(\w+)\b', content))
            pkg = pkg_groups.group(1)

            for td in typedef_enum_re.finditer(content):
                td_body = td.group(1)
                td_body = ' '.join([x.split('//')[0].strip()
                                    for x in td_body.split('\n')])
                td_name = td.group(2)
                kvs = [re.split('\s*=\s*', x.strip())
                       for x in td_body.split(',')]
                kvs = [(x[0], x[1]) if len(x) == 2 else (x[0], i)
                       for i, x in enumerate(kvs)]
                kvs = {k: val_to_int(v) for k, v in kvs}
                values = [v[0] for v in kvs.values()]
                sz = max(values)
                if not sz:
                    print(len(kvs))
                    sz = ceil(log2(len(kvs)+1))
                    print(f'>>> sz={sz}')
                fmt = 'hex' if sz >= 4 else 'bin'
                translations[pkg + '::' +
                             td_name] = fmt, sz, [(v, k) for k, (szz, v) in kvs.items()]

    for tr_type_name, (datafmt, sz, tr) in translations.items():
        translate = vcd.gtkw.make_translation_filter(
            tr, datafmt=datafmt, size=sz)
        gtkwave_dir = Path('gtkwave')
        gtkwave_dir.mkdir(exist_ok=True, parents=True)
        with open(gtkwave_dir / (tr_type_name + '.gwtr'), 'w') as f:
            print(f"writing translation of {tr_type_name} into {f.name}")
            f.write(translate)
    sys.exit(0)


BLUESPEC_PREFIX = os.environ.get('BLUESPEC_PREFIX')
bsc_exec = os.path.join(BLUESPEC_PREFIX, 'bin',
                        'bsc') if BLUESPEC_PREFIX else shutil.which("bsc")

if not BLUESPEC_PREFIX:
    BLUESPEC_PREFIX = os.path.dirname(os.path.dirname(bsc_exec))

print(f'BLUESPEC_PREFIX={BLUESPEC_PREFIX} bsc={bsc_exec}')

lib_paths = []

lib_paths.insert(0, '+')

vout_dir = Path.cwd() / 'gen_rtl'
bsc_out = Path.cwd() / '._bsc_'

verilog_paths = [f'{BLUESPEC_PREFIX}/lib/Verilog']

bsc_flags = [
    '-steps-max-intervals', '6000000',
    '-steps-warn-interval', '2000000',
    '-promote-warnings', 'ALL',
    '-show-compiles', '-show-module-use',
    '-show-version', '-show-range-conflict','-show-method-conf',
    '-bdir', str(bsc_out),
    '-info-dir', str(bsc_out),
]


if args.debug:
    bsc_flags += [
        # '-keep-fires',
        # '-keep-inlined-boundaries',
        # '-show-schedule',
        # '-sched-dot',
        '-sat-yices',
        '-remove-unused-modules',
        '-remove-false-rules',
        '-remove-starved-rules',
        '-no-keep-fires',
        '-no-keep-inlined-boundaries',
        '-aggressive-conditions',  # saw suspicious behavior with this
        '-O',
        '-no-show-timestamps', # regenerated files should be the same
        '-opt-undetermined-vals',
        '-unspecified-to', 'X',
    ]
else:
    bsc_flags += [
        '-remove-dollar',
        '-sat-yices',
        '-remove-unused-modules',
        '-remove-false-rules',
        '-remove-starved-rules',
        '-no-keep-fires',
        '-no-keep-inlined-boundaries',
        '-aggressive-conditions',  # saw suspicious behavior with this
        '-O',
        '-no-show-timestamps', # regenerated files should be the same
        '-opt-undetermined-vals',
        '-unspecified-to', 'X',
    ]


def prepend_to_file(filename, lines):
    with open(filename, 'r+') as f:
        content = f.read()
        f.seek(0, 0)
        f.write('\n'.join(lines) + '\n' + content)


def get_used_mods(use_dir: Path, mod: str):
    use_path = use_dir / f'{mod}.use'
    uses = []
    if use_path.exists():
        with open(use_path) as f:
            for l in f.readlines():
                l = l.strip()
                if l not in uses:
                    uses.append(l)
                    uses.extend([x for x in get_used_mods(
                        use_dir, l) if x not in uses])
    return uses


def bsc_generate_verilog():
    top_file = bluespec_sources[-1]
    top = rtl_settings['top']
    if vout_dir.exists():
        shutil.rmtree(vout_dir)
    vout_dir.mkdir(exist_ok=False)
    if not args.debug:
        if bsc_out.exists():
            shutil.rmtree(bsc_out)
    bsc_out.mkdir(exist_ok=True)

    for src in bluespec_sources:
        #     cmd = [bsc_exec] + bsc_flags + ['-u', src]
        dirname, basename = os.path.split(src)
        if dirname and dirname not in lib_paths:
            print(f"Adding {dirname} to BSV lib path")
            lib_paths.append(dirname)

    #     print(f'running {" ".join(cmd)}')
    #     subprocess.run(cmd, check=True)

    bsc_defines = rtl_settings.get('parameters', {})

    if args.debug:
        print("DEBUG!")
        bsc_defines['DEBUG']=1


    for param_name, param_value in bsc_defines.items():
        bsc_flags.extend([
            '-D', f'{param_name}={param_value}'
        ])

    cmd = [bsc_exec] + bsc_flags

    cmd += [
        '-p', ':'.join(lib_paths),
        # '-vsearch', ':'.join(verilog_paths),
        '-vdir', str(vout_dir),
        '-u',
        '-verilog',
        '-g', top, top_file
    ]

    print(f'running {" ".join(cmd)}')

    try:
        subprocess.run(cmd, check=True)
    except Exception as e:
        print(f"bsc failed with return code: {e.args[0]}")
        sys.exit(1)

    used_mods = get_used_mods(vout_dir, top)
    print(f'used_mods={used_mods}')
    for use in used_mods:
        verilog_name = f'{use}.v'
        if not (vout_dir / verilog_name).exists():
            for vpath in verilog_paths:
                for vfile in Path(vpath).glob(os.path.join('**', verilog_name)):
                    shutil.copy(vfile, vout_dir)

    verilog_sources = list(vout_dir.glob('*.v'))

    for v in verilog_sources:
        prepend_to_file(v, ['`define BSV_POSITIVE_RESET',
                            '`define BSV_NO_INITIAL_BLOCKS'])

    print(f'verilog_sources={verilog_sources}')

    return top


def test_verilator():
    top = bsc_generate_verilog()
    if not args.gen:
        run_sim(top)


def run_sim(top):
    verilog_sources = list(vout_dir.glob('*.v'))
    extra_args = [
        # '+define+BSV_POSITIVE_RESET=1',
        # + [f'-I{p}' for p in verilog_paths],
        '-Wno-STMTDLY', '-Wno-INITIALDLY',
        '--x-assign', 'unique',
        '--x-initial', 'unique',  # perf: fast
        '-O3',
    ]

    if args.debug:
        extra_args += [
            '--trace',
            '--trace-structs',
            '--trace-max-array', '64',
            '--trace-underscore',
            '--trace-max-width', '512',
        ]
    else:
        extra_args += [
            '-O3',
            # '--x-initial', 'unique',  # perf: fast, don't change
            # '--x-assign', 'fast',  # perf: fast
        ]

    cocotb_env = dict(COCOTB_REDUCED_LOG_FMT='1',
                      COCOTB_ANSI_OUTPUT='1',
                      RANDOM_SEED=args.seed,
                      )

    test_functions = args.tests

    if test_functions:
        print(f"Running the following test functions: {test_functions}")
        cocotb_env['TESTCASE'] = ','.join(test_functions)

    if args.debug:
        cocotb_env['WAVES'] = '1'

    # COMPILE_ARGS
    # SIM_ARGS
    # RUN_ARGS
    # EXTRA_ARGS <-> extra_args:
    # Passed to both the compile and execute phases of simulators with two rules,
    #  or passed to the single compile and run command for simulators which don’t
    #  have a distinct compilation stage.
    # PLUSARGS
    # SIM_BUILD

    sim = Verilator(extra_args=extra_args,
                    extra_env=cocotb_env,
                    plus_args=[
                        '+verilator+seed+50', '+verilator+rand+reset+2'],
                    verilog_sources=verilog_sources,
                    toplevel=top,
                    module=xeda_design['tb']['cocotb']['module']
                    )

    sim.run()


if __name__ == "__main__":
    test_verilator()
