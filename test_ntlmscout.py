"""Tests for ntlmscout's catch-all (path-agnostic) NTLM detection.

A host that enforces NTLM on *every* path (an IIS site-wide Windows Auth
filter, or an ADC / reverse proxy in front of the app) answers the whole
endpoint wordlist with a 401+NTLM challenge, so the discovered "endpoints"
are just the wordlist enumerating itself. The canary probe detects this and
collapses the false positives to a single, honest finding.
"""
import argparse
import unittest

import ntlmscout as ns


def _http(host, url, ntlm=True, port=443, proto="https", fingerprint=None,
          responded=True):
    return {
        "target": url, "protocol": proto, "host": host, "port": port,
        "url": url, "success": True, "responded": responded,
        "ntlm": {"target_name": "fd"} if ntlm else None,
        "fingerprint": fingerprint or {"netbios_computer": "HOST01"},
    }


def _canary(host, port=443, proto="https", ntlm=True, responded=True):
    url = "{}://{}:{}{}".format(proto, host, port, ns.canary_path())
    return _http(host, url, ntlm=ntlm, port=port, proto=proto, responded=responded)


def _dead_canary(host, port=443, proto="https"):
    """A canary that never reached the server (timeout / reset / rate-limit)."""
    c = _canary(host, port=port, proto=proto, ntlm=False, responded=False)
    c["success"] = False
    c["error"] = "TimeoutError: timed out"
    return c


class CanaryPathTests(unittest.TestCase):
    def test_canary_path_carries_marker(self):
        self.assertIn(ns.CANARY_MARKER, ns.canary_path())

    def test_canary_paths_are_unique(self):
        self.assertNotEqual(ns.canary_path(), ns.canary_path())

    def test_is_canary_result_matches_marker(self):
        self.assertTrue(ns.is_canary_result(_canary("h.example")))
        self.assertFalse(ns.is_canary_result(_http("h.example", "https://h.example/owa/")))


class CollapseCatchallTests(unittest.TestCase):
    def test_collapses_wordlist_to_one_endpoint_when_canary_challenges(self):
        host = "authwall.example"
        results = [_canary(host)]
        for path in ("/", "/owa/", "/EWS/Exchange.asmx", "/adfs/ls/"):
            results.append(_http(host, "https://" + host + path))

        out = ns.collapse_catchall_endpoints(results)

        # The synthetic canary path is never reported as an endpoint.
        self.assertFalse(any(ns.is_canary_result(r) for r in out))
        # Exactly one NTLM-bearing endpoint remains for this host:port.
        ntlm = [r for r in out if r.get("ntlm")]
        self.assertEqual(len(ntlm), 1)
        self.assertTrue(ntlm[0]["catchall"])
        self.assertEqual(ntlm[0]["catchall_collapsed"], 4)
        # The rest are still present (they may carry disclosed names) but are
        # no longer counted as NTLM endpoints.
        collapsed = [r for r in out if r.get("catchall") and not r.get("ntlm")]
        self.assertEqual(len(collapsed), 3)

    def test_representative_prefers_site_root(self):
        host = "h.example"
        results = [
            _canary(host),
            _http(host, "https://h.example/owa/"),
            _http(host, "https://h.example/"),
            _http(host, "https://h.example/EWS/"),
        ]
        out = ns.collapse_catchall_endpoints(results)
        rep = [r for r in out if r.get("ntlm")][0]
        self.assertEqual(rep["url"], "https://h.example/")

    def test_no_collapse_when_canary_does_not_challenge(self):
        host = "normal.example"
        results = [
            _http(host, "https://normal.example" + ns.canary_path(), ntlm=False),
            _http(host, "https://normal.example/owa/"),
            _http(host, "https://normal.example/EWS/"),
        ]
        out = ns.collapse_catchall_endpoints(results)
        self.assertEqual(sum(1 for r in out if r.get("ntlm")), 2)
        self.assertFalse(any(r.get("catchall") for r in out))

    def test_other_hosts_are_untouched(self):
        catchall_host, normal_host = "a.example", "b.example"
        results = [
            _canary(catchall_host),
            _http(catchall_host, "https://a.example/owa/"),
            _http(catchall_host, "https://a.example/"),
            _http(normal_host, "https://b.example/owa/"),
            _http(normal_host, "https://b.example/EWS/"),
        ]
        out = ns.collapse_catchall_endpoints(results)
        normal = [r for r in out if r["host"] == normal_host and r.get("ntlm")]
        self.assertEqual(len(normal), 2)
        self.assertFalse(any(r.get("catchall") for r in normal))

    def test_non_http_results_are_untouched(self):
        host = "h.example"
        smb = {"target": "h.example:445", "protocol": "smb", "host": host,
               "port": 445, "url": None, "success": True,
               "ntlm": {"target_name": "fd"}, "fingerprint": {}}
        results = [_canary(host), _http(host, "https://h.example/owa/"), smb]
        out = ns.collapse_catchall_endpoints(results)
        self.assertTrue([r for r in out if r["protocol"] == "smb"][0].get("ntlm"))


class PlanTargetsCanaryTests(unittest.TestCase):
    def _args(self, targets, no_discover=False):
        return argparse.Namespace(targets=targets, input_list=None,
                                  no_discover=no_discover, no_internal_ip=True)

    def test_adds_canaries_per_http_endpoint_when_discovering(self):
        jobs = ns.plan_targets(self._args(["https://h.example/"]))
        canaries = [j for j in jobs if ns.CANARY_MARKER in (j[3] or "")]
        self.assertEqual(len(canaries), ns.CANARY_PROBES)
        # Wordlist paths are still planned alongside the canaries.
        self.assertEqual(len(jobs), len(ns.HTTP_PATHS) + ns.CANARY_PROBES)

    def test_one_canary_set_per_endpoint_not_per_path(self):
        # A bare host sweeps several web ports; each gets its own canary set,
        # and the count does not scale with the wordlist.
        jobs = ns.plan_targets(self._args(["h.example"]))
        canaries = [j for j in jobs if ns.CANARY_MARKER in (j[3] or "")]
        endpoints = {(j[0], j[1], ns._job_port(j[0], j[2])) for j in jobs
                     if ns.CANARY_MARKER in (j[3] or "")}
        self.assertEqual(len(canaries), len(endpoints) * ns.CANARY_PROBES)
        self.assertGreater(len(endpoints), 1)

    def test_no_canary_without_discovery(self):
        jobs = ns.plan_targets(self._args(["https://h.example/"], no_discover=True))
        self.assertFalse(any(ns.CANARY_MARKER in (j[3] or "") for j in jobs))


class CanaryVerdictTests(unittest.TestCase):
    """A canary that never reached the server proves nothing either way."""

    def test_challenge_means_catchall(self):
        self.assertEqual(ns._canary_verdict([_canary("h.example")]), "catchall")

    def test_definite_non_challenge_means_specific(self):
        c = _canary("h.example", ntlm=False)
        self.assertEqual(ns._canary_verdict([c]), "specific")

    def test_failed_canary_means_unknown(self):
        self.assertEqual(ns._canary_verdict([_dead_canary("h.example")]), "unknown")

    def test_one_live_challenge_outweighs_a_failure(self):
        verdict = ns._canary_verdict([_dead_canary("h.example"), _canary("h.example")])
        self.assertEqual(verdict, "catchall")

    def test_one_live_non_challenge_outweighs_a_failure(self):
        verdict = ns._canary_verdict([_dead_canary("h.example"),
                                      _canary("h.example", ntlm=False)])
        self.assertEqual(verdict, "specific")

    def test_no_canary_at_all_is_unknown(self):
        self.assertEqual(ns._canary_verdict([]), "unknown")


class CollapseFailOpenTests(unittest.TestCase):
    """With every canary dead, fall back on the wordlist hit ratio rather than
    silently reporting the whole wordlist as distinct endpoints."""

    def _wordlist(self, host, hits, misses):
        out = []
        for i in range(hits):
            out.append(_http(host, "https://%s/hit%d/" % (host, i)))
        for i in range(misses):
            out.append(_http(host, "https://%s/miss%d/" % (host, i), ntlm=False))
        return out

    def test_dead_canary_with_a_saturated_wordlist_still_collapses(self):
        host = "authwall.example"
        results = [_dead_canary(host)] + self._wordlist(host, hits=40, misses=0)
        out = ns.collapse_catchall_endpoints(results)
        ntlm = [r for r in out if r.get("ntlm")]
        self.assertEqual(len(ntlm), 1)
        self.assertTrue(ntlm[0]["catchall"])
        self.assertEqual(ntlm[0]["catchall_collapsed"], 40)

    def test_dead_canary_with_a_selective_wordlist_does_not_collapse(self):
        host = "exchange.example"
        results = [_dead_canary(host)] + self._wordlist(host, hits=8, misses=70)
        out = ns.collapse_catchall_endpoints(results)
        self.assertEqual(sum(1 for r in out if r.get("ntlm")), 8)
        self.assertFalse(any(r.get("catchall") for r in out))

    def test_dead_canary_with_too_small_a_sample_does_not_collapse(self):
        host = "tiny.example"
        results = [_dead_canary(host)] + self._wordlist(host, hits=3, misses=0)
        out = ns.collapse_catchall_endpoints(results)
        self.assertEqual(sum(1 for r in out if r.get("ntlm")), 3)
        self.assertFalse(any(r.get("catchall") for r in out))

    def test_unreachable_paths_do_not_count_toward_the_ratio(self):
        # 12 hits, and 60 paths that never reached the server. The ratio is
        # computed over paths that actually answered, so this still collapses.
        host = "flaky.example"
        dead = [_http(host, "https://%s/dead%d/" % (host, i), ntlm=False,
                      responded=False) for i in range(60)]
        results = [_dead_canary(host)] + self._wordlist(host, hits=12, misses=0) + dead
        out = ns.collapse_catchall_endpoints(results)
        ntlm = [r for r in out if r.get("ntlm")]
        self.assertEqual(len(ntlm), 1)
        self.assertTrue(ntlm[0]["catchall"])

    def test_a_live_canary_still_overrides_the_ratio(self):
        # The canary answered and did not challenge, so the host is genuinely
        # path-specific even though every probed path happened to challenge.
        host = "picky.example"
        results = [_canary(host, ntlm=False)] + self._wordlist(host, hits=40, misses=0)
        out = ns.collapse_catchall_endpoints(results)
        self.assertEqual(sum(1 for r in out if r.get("ntlm")), 40)
        self.assertFalse(any(r.get("catchall") for r in out))


class CanaryCountTests(unittest.TestCase):
    def _args(self, targets, no_discover=False):
        return argparse.Namespace(targets=targets, input_list=None,
                                  no_discover=no_discover, no_internal_ip=True)

    def test_plans_more_than_one_canary_per_endpoint(self):
        jobs = ns.plan_targets(self._args(["https://h.example/"]))
        canaries = [j for j in jobs if ns.CANARY_MARKER in (j[3] or "")]
        self.assertEqual(len(canaries), ns.CANARY_PROBES)
        self.assertGreater(ns.CANARY_PROBES, 1)

    def test_canary_paths_within_an_endpoint_differ(self):
        jobs = ns.plan_targets(self._args(["https://h.example/"]))
        canaries = [j[3] for j in jobs if ns.CANARY_MARKER in (j[3] or "")]
        self.assertEqual(len(set(canaries)), len(canaries))


if __name__ == "__main__":
    unittest.main()
