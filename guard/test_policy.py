import copy
import json
from pathlib import Path
import tempfile
import unittest
from policy import decide, load_scope, model_endpoint


class Allowlist(unittest.TestCase):
    def setUp(self):
        self.scope = {'schema': 'redrouter.scope/v1', 'status': 'active',
                      'engagement': {'name': 'Unit fixture', 'type': 'internal'},
                      'in_scope': [{'type': 'url', 'value': 'https://staging:443/api'}]}

    def decision(self, host='staging', protocol='http', port=443, path='/api'):
        return decide(self.scope, host, port, protocol, model_endpoint('https://model:443/v1'), now=100, path=path)

    def test_in_scope(self):
        self.scope['in_scope'][0]['value'] = 'http://staging:8000/api'
        self.assertEqual(self.decision(port=8000)[0], 'allow')
        self.assertEqual(self.decision(port=80)[0], 'block')
        self.assertEqual(self.decision(port=8000, path='/other')[0], 'block')
        self.assertEqual(self.decision(host='model', protocol='connect')[0], 'allow')
        self.assertEqual(self.decision(host='model', protocol='dns', port=53)[0], 'allow')
        self.assertEqual(self.decision(host='model')[0], 'block')
        self.assertEqual(self.decision(host='model', protocol='connect', port=22)[0], 'block')
        self.assertIsNone(model_endpoint('-'))
        with self.assertRaises(ValueError):
            model_endpoint('http://model:443')
        self.assertEqual(self.decision(host='elsewhere')[0], 'block')
        self.scope['in_scope'][0]['value'] = 'https://staging/api'
        self.assertEqual(self.decision(protocol='connect')[0], 'block')  # invisible path

    def test_out_of_scope_wins(self):
        self.scope['in_scope'] = [{'type': 'domain', 'value': 'staging'}]
        self.scope['out_of_scope'] = copy.deepcopy(self.scope['in_scope'])
        self.assertEqual(self.decision()[1], 'out-of-scope')
        self.assertEqual(self.decision()[2], self.scope['out_of_scope'][0])
        self.scope['out_of_scope'].append({'type': 'domain', 'value': 'model'})
        self.assertEqual(self.decision(host='model', protocol='connect')[1], 'out-of-scope')

    def test_wildcard_domain(self):
        self.scope['in_scope'] = [{'type': 'domain', 'value': '*.example.test'}]
        self.assertEqual(self.decision(host='A.B.EXAMPLE.TEST.')[0], 'allow')
        for name in ('example.test', 'notexample.test'):
            self.assertEqual(self.decision(host=name)[0], 'block')

    def test_cidr(self):
        self.scope['in_scope'] = [{'type': 'cidr', 'value': '192.0.2.0/24'},
                                  {'type': 'cidr', 'value': '2001:db8::/32'}]
        self.assertEqual(self.decision(host='192.0.2.5')[0], 'allow')
        self.assertEqual(self.decision(host='2001:db8::1')[0], 'allow')
        self.assertEqual(self.decision(host='192.0.3.5')[0], 'block')
        self.scope['in_scope'] = [{'type': 'cidr', 'value': '::/0'}]
        for name in ('fe80::1%eth0', 'fe80::1%1', '::ffff:192.0.2.5'):
            self.assertEqual(self.decision(host=name)[0], 'block')

    def test_http_paths(self):
        self.scope['in_scope'] = [{'type': 'url', 'value': 'http://staging:443/api/'}]
        self.scope['out_of_scope'] = [{'type': 'url', 'value': 'http://staging:443/api/admin'}]
        for path in ('/api', '/api/', '/api/ok', '/api/administrator'):
            self.assertEqual(self.decision(path=path)[0], 'allow', path)
        for path in ('/api/admin', '/api/%61dmin/secret'):
            self.assertEqual(self.decision(path=path)[1], 'out-of-scope', path)
        for path in ('/apix', '/api-internal', '/api/../admin', '/api/./admin', '/api//admin',
                     '/api/%2e%2e/admin', '/api%2Fadmin', '/api/%5cadmin', '/api\\admin'):
            self.assertEqual(self.decision(path=path)[0], 'block', path)
        self.scope['in_scope'][0]['value'] = 'http://staging:443/'
        self.assertEqual(self.decision(path='/x/../api/admin')[0], 'block')

    def test_named_exclusion_covers_ip_grant(self):
        self.scope['in_scope'] = [{'type': 'cidr', 'value': '192.0.2.0/24'}]
        entry = {'type': 'domain', 'value': 'production'}
        self.scope['out_of_scope'] = [entry]
        for name, model in (('192.0.2.5', None), ('model', ('model', 443))):
            decision = decide(self.scope, name, 443, 'connect', model, now=100,
                              addresses=['192.0.2.5'], named_addresses={'production': ['192.0.2.5']})
            self.assertEqual(decision, ('block', 'out-of-scope', entry))

    def test_loopback_url_mapping(self):
        self.scope['in_scope'] = [{'type': 'url', 'value': 'http://localhost:8000/api'}]
        self.assertEqual(self.decision(host='host.docker.internal', port=8000)[0], 'allow')
        for name, port, path in (('host.docker.internal', 22, '/api'),
                                 ('host.docker.internal', 8000, '/other'),
                                 ('localhost', 8000, '/api'), ('127.0.0.1', 8000, '/api')):
            self.assertEqual(self.decision(host=name, port=port, path=path)[0], 'block')
        self.scope['out_of_scope'] = [{'type': 'ip', 'value': '127.0.0.1'}]
        self.assertEqual(self.decision(host='host.docker.internal', port=8000)[1], 'out-of-scope')

    def test_action_json_scope(self):
        self.scope['window'] = {'starts': '1970-01-01T00:00:00+00:00', 'expires': '1970-01-01T00:03:00Z'}
        self.scope['techniques'] = {}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'scope.json'
            path.write_text(json.dumps(self.scope))
            self.scope = load_scope(path)
        self.assertEqual(self.decision(protocol='dns', port=53)[0], 'allow')
        self.scope['window']['expires'] = '1970-01-01T00:03:00+01:00'
        self.assertEqual(self.decision(protocol='dns', port=53)[0], 'block')

    def test_expired(self):
        self.scope['window'] = {'starts': '1970-01-01T00:00:00Z', 'expires': '1970-01-01T00:01:40Z'}
        self.assertEqual(self.decision()[1], 'scope-expired')
        self.assertEqual(self.decision(host='model')[1], 'scope-expired')

    def test_revoked(self):
        self.scope['status'] = 'revoked'
        self.assertEqual(self.decision()[1], 'scope-revoked')
        self.assertEqual(self.decision(host='model')[1], 'scope-revoked')


if __name__ == '__main__':
    unittest.main()
