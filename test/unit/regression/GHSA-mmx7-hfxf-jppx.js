// https://github.com/advisories/GHSA-mmx7-hfxf-jppx (CVE-2026-67316)
// axios.get/delete/head/options must not read an inherited `data` from Object.prototype
// before the config is normalized, otherwise a polluted prototype adds a body to bodyless requests.

import assert from 'assert';
import axios from '../../../index.js';

async function sentData(method, config) {
  let seen = 'adapter not reached';

  await axios[method]('http://example.invalid/', Object.assign({
    adapter: async (cfg) => {
      seen = cfg.data;
      return {data: '', status: 200, statusText: 'OK', headers: {}, config: cfg};
    }
  }, config));

  return seen;
}

describe('regression::GHSA-mmx7-hfxf-jppx bodyless method aliases', () => {
  afterEach(() => {
    delete Object.prototype.data;
  });

  ['get', 'delete', 'head', 'options'].forEach((method) => {
    it(`axios.${method}() should ignore an inherited Object.prototype.data`, async () => {
      Object.prototype.data = 'POLLUTED-BODY';

      assert.strictEqual(await sentData(method), undefined);
    });
  });

  it('axios.delete() should still send an own data property', async () => {
    assert.strictEqual(await sentData('delete', {data: 'own-body'}), 'own-body');
  });
});
