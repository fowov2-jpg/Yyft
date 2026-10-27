import base64
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import checker

NOW = datetime(2026, 10, 25, 10, 0, tzinfo=timezone.utc)
UUID = '01234567-89ab-cdef-0123-456789abcdef'
LINKS = [
    f'vless://{UUID}@good.example.org:443?security=reality&pbk=abc&sni=example.com#Москва 🇷🇺',
    'vmess://' + base64.urlsafe_b64encode(json.dumps({'add': 'good.example.org', 'port': 443, 'id': UUID, 'ps': '東京', 'tls': 'tls', 'net': 'ws', 'path': '/v'}).encode()).decode().rstrip('=') + '#тест',
    'trojan://secret@good.example.org:443?security=tls&sni=example.com#Париж',
    'ss://' + base64.urlsafe_b64encode(b'aes-128-gcm:secret').decode().rstrip('=') + '@good.example.org:443#Санкт-Петербург',
]

class ContractTest(unittest.TestCase):
    def test_fingerprints_cross_language_vectors(self):
        fixture = json.loads((Path(__file__).parent / 'fingerprints.json').read_text())
        self.assertEqual(len(fixture), 4)
        for uri, digest in zip(LINKS, fixture):
            self.assertEqual(checker.fingerprint(uri), digest['fingerprint'])
            self.assertEqual(uri, digest['uri'])
            self.assertEqual(len(checker.fingerprint(uri)), 64)
            self.assertEqual(checker.fingerprint(uri), hashlib.sha256(uri.split('#')[0].encode()).hexdigest())
            self.assertEqual(checker.fingerprint('  ' + uri + '  '), digest['fingerprint'])
            self.assertEqual(checker.fingerprint(uri.split('#')[0] + '#Other 标签'), digest['fingerprint'])

    def test_ssrf_blocks_non_global_ip_literals(self):
        for bad in ['127.0.0.1', '10.0.0.1', '192.168.10.12', '169.254.169.254', '100.64.0.3', '::1', 'fc00::1', 'fe80::1', 'localhost', 'router.local', '127.0.0.1.nip.io']:
            with self.subTest(bad=bad), self.assertRaises((ValueError, OSError)):
                checker.pin_address(bad, 443, lambda *a, **kw: [(None,None,None,None,('127.0.0.1',443))])

    def test_pin_dns_public_ip_and_rebinding(self):
        def resolve(*_args, **_kwargs):
            return [(None,None,None,None,('8.8.8.8',443)), (None,None,None,None,('1.1.1.1',443))]
        self.assertEqual(checker.pin_address('example.com', 443, resolve), '1.1.1.1')
        def evil(*_args, **_kwargs):
            return [(None,None,None,None,('8.8.8.8',443)), (None,None,None,None,('10.0.0.1',443))]
        with self.assertRaises(ValueError):
            checker.pin_address('example.com',443, evil)

    def test_outbounds_pinned_never_loopback_or_user_supplied_code(self):
        resolver = lambda *a, **kw: [(None,None,None,None,('8.8.8.8',443))]
        for link in LINKS:
            outbound = checker.outbound_from_uri(link, resolver)
            self.assertEqual(outbound['tag'], 'proxy')
            setting = outbound['settings'].get('vnext', outbound['settings'].get('servers'))[0]
            self.assertEqual(setting['address'], '8.8.8.8')
            self.assertEqual(setting['port'], 443)
        for uri in ['ssh://x@example.com:443', 'vless://x@127.0.0.1:443?security=reality&pbk=x', 'vless://x@server:443?security=tls', 'vless://x@example.com:443?security=none']:
            with self.assertRaises((ValueError, TypeError)):
                checker.outbound_from_uri(uri, resolver)

    def test_source_extraction_plain_and_b64(self):
        text = '\n'.join(LINKS)
        self.assertEqual(checker.extract_links(text.encode()), LINKS)
        self.assertEqual(checker.extract_links(base64.b64encode(text.encode())), LINKS)
        self.assertEqual(checker.extract_links(b' #profile-title: abc\n' + base64.b64encode(text.encode())), LINKS)

    def test_balanced_rotation_limits_and_dedup(self):
        sources = {'a':[f'vless://test@host:443?k={n}' for n in range(40)], 'b':['ss://same', 'ss://same']}
        a = checker.pick_balanced(sources,1,16)
        b = checker.pick_balanced(sources,2,16)
        self.assertEqual(len(a),16)
        self.assertNotEqual(a,b)
        self.assertEqual(len({r['fingerprint'] for r in a}),len(a))
        self.assertEqual(a[1]['source_id'],'b')
        self.assertLessEqual(checker.MAX_WORKERS,2)
        self.assertLessEqual(checker.MAX_PER_RUN,80)

    def test_public_candidate_source_ids_accepted_by_android_248(self):
        # Version 2.4.8 accepts existing ConfigSources ids, not arbitrary source ids.
        # Telega requires a new Android app build to become directly importable.
        self.assertIn("au1rxx", checker.SOURCES)
        self.assertNotIn("au1rxx_vless", checker.SOURCES)
        candidate = LINKS[0]
        sampled = [{"source_id": "au1rxx", "fingerprint": checker.fingerprint(candidate), "raw": candidate}]
        checked = [{"fingerprint": checker.fingerprint(candidate), "https_ok": True,
                    "youtube_page_ok": False, "https_latency_ms": 230}]
        result = json.loads(checker.pack_public_candidates(checked, sampled, NOW))
        self.assertEqual([c["source_id"] for c in result["candidates"]], ["au1rxx"])

    def test_additional_sources_are_fixed_public_https_only(self):
        for source in ("telega_ru", "au1rxx"):
            self.assertIn(source, checker.SOURCES)
            self.assertLessEqual(len(checker.SOURCES[source]), 2)
            for url in checker.SOURCES[source]:
                self.assertTrue(url.startswith("https://raw.githubusercontent.com/"))
                self.assertNotIn("?", url)
        self.assertLessEqual(checker.MAX_PER_RUN, 24)
        self.assertLessEqual(checker.MAX_WORKERS, 2)

    def test_new_source_rotation_no_special_trust(self):
        sample = {sid: [LINKS[i % len(LINKS)] + f"&probe={i}#{sid}"]
                  for i, sid in enumerate(["telega_ru", "au1rxx", "radikal", "morpheus"])}
        chosen = checker.pick_balanced(sample, 31, 4)
        self.assertEqual({entry["source_id"] for entry in chosen}, set(sample))
        self.assertEqual(len({entry["fingerprint"] for entry in chosen}), 4)
        for entry in chosen:
            self.assertFalse("https_ok" in entry)
        self.assertFalse(checker.pack_public_candidates([], chosen, NOW).find(b'"uri"') >= 0)

    def test_ttl_and_known_failure_no_false_liveness(self):
        base = {'fingerprint':'a'*64,'source_id':'3inker','https_ok':True,'youtube_page_ok':False,'https_latency_ms':120,'checked_at':checker.iso(NOW-timedelta(hours=2))}
        prev = {'schema':1,'results':[base]}
        retained = json.loads(checker.pack_feed([], prev, NOW))['results']
        self.assertEqual(retained[0]['checked_at'],base['checked_at'])
        failed = {**base,'https_ok':False}
        self.assertEqual(json.loads(checker.pack_feed([failed],prev,NOW))['results'],[])
        stale = {**base,'checked_at':checker.iso(NOW-timedelta(hours=8,seconds=1))}
        self.assertEqual(checker.accepted_previous({'schema':1,'results':[stale]},NOW),[])
        self.assertEqual(json.loads(checker.pack_feed([],{},NOW))['results'],[])
        self.assertEqual(json.loads(checker.pack_feed([],{},NOW))['schema'],1)

    def test_public_candidate_feed_only_real_positive_public_sources(self):
        a, b = LINKS[:2]
        sampled = [{"fingerprint": checker.fingerprint(a), "source_id": "avia", "raw": a},
                   {"fingerprint": checker.fingerprint(b), "source_id": "hamed", "raw": b}]
        checked = [{"fingerprint": checker.fingerprint(a), "https_ok": True, "youtube_page_ok": True,
                    "https_latency_ms": 120},
                   {"fingerprint": checker.fingerprint(b), "https_ok": False, "youtube_page_ok": False,
                    "https_latency_ms": None}]
        result = json.loads(checker.pack_public_candidates(checked, sampled, NOW))
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["uri"], a.split("#")[0])
        self.assertEqual(result["candidates"][0]["fingerprint"], checker.fingerprint(a))
        self.assertEqual(result["valid_until"], checker.iso(NOW + timedelta(hours=2)))

    def test_public_candidate_feed_rejects_unknown_sources(self):
        a = LINKS[0]
        sampled = [{"fingerprint": checker.fingerprint(a), "source_id": "other", "raw": a}]
        checked = [{"fingerprint": checker.fingerprint(a), "https_ok": True,
                    "youtube_page_ok": True, "https_latency_ms": 120}]
        self.assertEqual(json.loads(checker.pack_public_candidates(checked, sampled, NOW))["candidates"], [])

    def test_feed_no_secrets_and_bounded(self):
        node = {'fingerprint':'b'*64,'source_id':'3inker','https_ok':True,'youtube_page_ok':True,'https_latency_ms':200}
        result = checker.pack_feed([node],{},NOW)
        self.assertNotIn(b'vless://',result)
        self.assertNotIn(b'password',result)
        self.assertLessEqual(len(result),checker.MAX_FEED_BYTES)
        feed = json.loads(result)
        self.assertEqual(feed['results'][0]['checked_at'],checker.iso(NOW))
        self.assertEqual(feed['valid_until'],checker.iso(NOW+timedelta(hours=6)))

if __name__ == '__main__': unittest.main()
