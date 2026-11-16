import copy, gzip, json, os, struct, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import gate_candidate as g
import module_inventory as mi

DATA = Path(__file__).parents[2] / 'data' / 'baseline'
VERMAGIC = '4.9.190+ SMP preempt mod_unload modversions aarch64'


def elf(imports=None, exports=None, vermagic=VERMAGIC, versions=True, symtab=True):
    """Minimal ARM64 relocatable ELF64 with .modinfo, __versions and absolute __crc_ export symbols."""
    names = [b'', b'.modinfo', b'__versions', b'.symtab', b'.strtab', b'.shstrtab']
    shstr = b''.join(n + b'\0' for n in names); off = {}
    p = 0
    for n in names:
        off[n] = p; p += len(n) + 1
    modinfo = b'license=GPL\0vermagic=' + vermagic.encode() + b'\0'
    ver = b''.join(struct.pack('<Q56s', c, s.encode()) for s, c in (imports or {}).items())
    strtab = b'\0'; sym = b'\0' * 24
    for s, c in (exports or {}).items():
        sym += struct.pack('<IBBHQQ', len(strtab), 0, 0, 0xfff1, c, 0); strtab += b'__crc_' + s.encode() + b'\0'
    bodies = [b'', modinfo, ver, sym, strtab, shstr]
    keep = [True, True, versions, symtab, symtab, True]
    out = bytearray(64); secs = []
    for i, b in enumerate(bodies):
        if not keep[i]:
            secs.append(None); continue
        secs.append((len(out), len(b))); out += b
    # drop sections that are absent by renaming them so lookup fails
    shoff = len(out)
    for i, n in enumerate(names):
        if keep[i]:
            nm, (o, size) = off[n], secs[i] if secs[i] else (0, 0)
        else:
            nm, (o, size) = 0, (0, 0)
        out += struct.pack('<IIQQQQIIQQ', nm, 3 if n in (b'.symtab', b'.strtab', b'.shstrtab') and i else 1, 0, 0, o, size, 0, 0, 1, 24 if n == b'.symtab' else 0)
    out[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    struct.pack_into('<HHIQQQIHHHHHH', out, 16, 1, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(names), 5)
    return bytes(out)


def image(release='4.9.190+', vermagic=VERMAGIC):
    k = b'\0' * 50 + f'Linux version {release} (x@y) #1 SMP'.encode() + b'\0' + vermagic.replace('4.9.190+', release).encode() + b'\0' + b'\0' * 50
    return b'junk' + gzip.compress(k) + b'\0dtb'


KERNEL = {f'ksym{i}': 0x1000 + i for i in range(1200)}
KERNEL.update(module_layout=0xAAAA0001, cdev_add=0xAAAA0002, wmt_dummy_kernel=0xAAAA0003)


def inventory():
    mods = {}
    for n in g.EXPECTED:
        imp = {'module_layout': KERNEL['module_layout'], 'cdev_add': KERNEL['cdev_add']}
        mods[n] = dict(vermagic=VERMAGIC, imports=imp, exports={})
    mods['wmt_drv']['exports'] = {'wmt_api': 0xBBBB0001}
    mods['wlan_drv_gen4m']['imports']['wmt_api'] = 0xBBBB0001
    mods['wmt_chrdev_wifi']['imports']['wmt_api'] = 0xBBBB0001
    return {'modules': mods}


def symvers(kernel=None, extra=''):
    return ''.join(f'0x{c:08x}\t{s}\tvmlinux\tEXPORT_SYMBOL\n' for s, c in (kernel or KERNEL).items()) + extra


class Gate(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(); self.r = Path(self.t.name)
        self.inv = inventory()

    def tearDown(self): self.t.cleanup()

    def run_gate(self, inv=None, kernel=None, release='4.9.190+', vermagic=VERMAGIC, strict=False, ship=None, raw_inv=None):
        (self.r / 'inv.json').write_text(raw_inv if raw_inv is not None else json.dumps(self.inv if inv is None else inv))
        (self.r / 'sym').write_text(symvers(kernel))
        (self.r / 'img').write_bytes(image(release, vermagic))
        if ship:
            (self.r / 'ship.json').write_text(json.dumps({'shipping_export_crcs': ship}))
        return g.gate(self.r / 'sym', self.r / 'img', self.r / 'inv.json', self.r / 'ship.json' if ship else None, strict)

    def test_pass(self):
        r = self.run_gate(); self.assertEqual(r['gate'], 'PASS', r['problems']); self.assertTrue(r['necessary_not_sufficient'])

    def test_wrong_release(self):
        self.assertEqual(self.run_gate(release='4.9.117+')['gate'], 'FAIL')

    def test_vermagic_mismatch(self):
        self.inv['modules']['bt_drv']['vermagic'] = '4.9.190+ SMP mod_unload aarch64'
        self.assertIn('vermagic', ' '.join(self.run_gate()['problems']))

    def test_changed_kernel_crc(self):
        k = dict(KERNEL, cdev_add=1); r = self.run_gate(kernel=k)
        self.assertEqual(r['gate'], 'FAIL'); self.assertTrue(all(m['failures'] for m in r['modules'].values()))

    def test_missing_kernel_symbol_fails(self):
        k = {s: c for s, c in KERNEL.items() if s != 'cdev_add'}
        self.assertEqual(self.run_gate(kernel=k)['gate'], 'FAIL')

    def test_missing_module_layout_fails(self):
        del self.inv['modules']['fpsgo']['imports']['module_layout']
        self.assertEqual(self.run_gate()['gate'], 'FAIL')

    def test_provider_crc_changed_and_provider_missing(self):
        self.inv['modules']['wmt_drv']['exports']['wmt_api'] = 7
        r = self.run_gate(); self.assertEqual(r['gate'], 'FAIL'); self.assertTrue(any('provider CRC' in str(m['first']) for m in r['modules'].values()))
        self.inv = inventory(); self.inv['modules']['wmt_drv']['exports'] = {}
        r = self.run_gate(); self.assertEqual(r['gate'], 'FAIL'); self.assertTrue(any('unresolved' in str(m['first']) for m in r['modules'].values()))

    def test_module_cannot_provide_its_own_import(self):
        self.inv['modules']['wlan_drv_gen4m']['exports'] = {'wmt_api': 0xBBBB0001}
        self.inv['modules']['wmt_drv']['exports'] = {}
        self.assertEqual(self.run_gate()['gate'], 'FAIL')

    def test_empty_or_missing_inventory_rejected(self):
        for raw in ('{}', '{"modules": {}}'):
            with self.assertRaises(ValueError): self.run_gate(raw_inv=raw)
        with self.assertRaises(ValueError): g.gate(self.r / 'sym', self.r / 'img', self.r / 'nope.json')

    def test_incomplete_or_extra_module_set(self):
        del self.inv['modules']['gps_drv']
        self.assertIn('missing', ' '.join(self.run_gate()['problems']))
        self.inv = inventory(); self.inv['modules']['surprise'] = copy.deepcopy(self.inv['modules']['bt_drv'])
        self.assertIn('extra', ' '.join(self.run_gate()['problems']))

    def test_symvers_validation(self):
        (self.r / 'bad').write_text('0x1\tonly\n')
        with self.assertRaises(ValueError): g.read_symvers(self.r / 'bad')
        (self.r / 'few').write_text(symvers({'a': 1}))
        with self.assertRaises(ValueError): g.read_symvers(self.r / 'few')
        (self.r / 'dup').write_text(symvers(extra='0x00000009\tksym1\tvmlinux\tEXPORT_SYMBOL\n'))
        with self.assertRaises(ValueError): g.read_symvers(self.r / 'dup')

    def test_in_tree_module_rows_do_not_satisfy_kernel_imports(self):
        k = {s: c for s, c in KERNEL.items() if s != 'cdev_add'}
        (self.r / 'sym').write_text(symvers(k, '0x%08x\tcdev_add\tdrivers/x/y\tEXPORT_SYMBOL\n' % KERNEL['cdev_add']))
        (self.r / 'img').write_bytes(image()); (self.r / 'inv.json').write_text(json.dumps(self.inv))
        self.assertEqual(g.gate(self.r / 'sym', self.r / 'img', self.r / 'inv.json')['gate'], 'FAIL')

    def test_export_drift_reported_not_gated_unless_strict(self):
        ship = dict(KERNEL, ksym5=999, gone=1)
        r = self.run_gate(ship=ship); self.assertEqual((r['gate'], r['export_drift'], r['shipping_exports_absent']), ('PASS', 1, 1))
        self.assertEqual(self.run_gate(ship=ship, strict=True)['gate'], 'FAIL')

    def test_bad_image(self):
        (self.r / 'img').write_bytes(b'no gzip here')
        with self.assertRaises(ValueError): g.kernel_identity(self.r / 'img')


class Inventory(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(); self.r = Path(self.t.name)

    def tearDown(self): self.t.cleanup()

    def test_parse_roundtrip(self):
        (self.r / 'a.ko').write_bytes(elf({'module_layout': 5, 'x': 6}, {'wmt_api': 7}))
        m = mi.inventory(self.r)['modules']['a']
        self.assertEqual((m['imports'], m['exports'], m['vermagic']), ({'module_layout': 5, 'x': 6}, {'wmt_api': 7}, VERMAGIC))

    def test_rejections(self):
        with self.assertRaises(ValueError): mi.inventory(self.r)  # empty directory
        for name, blob in {'garbage': b'not elf', 'noversions': elf({'a': 1}, versions=False), 'emptyversions': elf({}),
                           'nosymtab': elf({'a': 1}, symtab=False)}.items():
            (self.r / 'x.ko').write_bytes(blob)
            with self.subTest(name), self.assertRaises(ValueError): mi.parse(self.r / 'x.ko')
        (self.r / 'x.ko').write_bytes(elf({'a': 1})[:100])
        with self.assertRaises((ValueError, struct.error)): mi.parse(self.r / 'x.ko')

    @unittest.skipUnless(os.environ.get('SHIPPING_MODULES'), 'actual shipping modules not available')
    def test_committed_inventory_matches_real_modules(self):
        real = mi.inventory(os.environ['SHIPPING_MODULES'])
        self.assertEqual(real, json.loads((DATA / 'shipping-module-inventory.json').read_text()))


class RealData(unittest.TestCase):
    def test_inventory_resolves_against_shipping_kernel_plus_module_providers(self):
        inv = json.loads((DATA / 'shipping-module-inventory.json').read_text())['modules']
        ship = json.loads((DATA / 'shipping-export-crcs.json').read_text())['shipping_export_crcs']
        self.assertEqual(sorted(inv), g.EXPECTED)
        prov = {s: c for m in inv.values() for s, c in m['exports'].items()}
        for n, m in inv.items():
            for s, c in m['imports'].items():
                self.assertEqual(ship[s] if s in ship else prov[s], c, (n, s))

    @unittest.skipUnless(os.environ.get('SHIPPING_CARRIER_IMAGE'), 'retained boot carrier image not available')
    def test_positive_control_real_shipping_kernel_passes(self):
        # shipping kernel image + its own recovered export table as Module.symvers must PASS; the 4.9.117 build must not
        with tempfile.TemporaryDirectory() as t:
            ship = json.loads((DATA / 'shipping-export-crcs.json').read_text())['shipping_export_crcs']
            sv = Path(t) / 'Module.symvers'; sv.write_text(symvers(ship))
            d = Path(os.environ['SHIPPING_CARRIER_IMAGE']).read_bytes()
            ks = struct.unpack_from('<I', d, 8)[0]; page = struct.unpack_from('<I', d, 36)[0]
            img = Path(t) / 'kernel.gz'; img.write_bytes(d[page:page + ks])
            r = g.gate(sv, img, DATA / 'shipping-module-inventory.json', DATA / 'shipping-export-crcs.json', True)
            self.assertEqual((r['gate'], r['export_drift']), ('PASS', 0), r['problems'])


class ConfigDrift(unittest.TestCase):
    def test_drift_lists_changed_dropped_added(self):
        import config_drift
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / 'a').write_text('CONFIG_A=y\n# CONFIG_B is not set\nCONFIG_C=\"x\"\nCONFIG_GONE=y\n# CONFIG_OFF is not set\n')
            (Path(t) / 'b').write_text('CONFIG_A=n\nCONFIG_C=\"x\"\nCONFIG_NEW=y\n')
            r = config_drift.drift(Path(t) / 'a', Path(t) / 'b')
        self.assertEqual((r['changed'], r['dropped'], r['added']), ({'CONFIG_A': ['y', 'n']}, {'CONFIG_GONE': 'y'}, {'CONFIG_NEW': 'y'}))


if __name__ == '__main__':
    unittest.main()
