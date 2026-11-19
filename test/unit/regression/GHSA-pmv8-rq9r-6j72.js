// https://github.com/advisories/GHSA-pmv8-rq9r-6j72 (CVE-2026-67312)
// https://github.com/advisories/GHSA-42h9-826w-cgv3 (CVE-2026-67313)
// formDataToJSON must reject field names nested deeper than the limit with an AxiosError
// instead of overflowing the call stack with a RangeError.

import assert from 'assert';
import axios from '../../../index.js';
import AxiosError from '../../../lib/core/AxiosError.js';
import formDataToJSON from '../../../lib/helpers/formDataToJSON.js';

// Minimal FormData-shaped class: the global FormData does not exist on Node < 18, and
// utils.isFormData rejects plain objects that inherit directly from Object.prototype.
class FakeFormData {
  constructor(entries) {
    this.items = entries;
  }

  append() {}

  entries() {
    return this.items[Symbol.iterator]();
  }

  [Symbol.iterator]() {
    return this.items[Symbol.iterator]();
  }

  toString() {
    return '[object FormData]';
  }
}

const fakeFormData = (entries) => new FakeFormData(entries);

const deepKey = (depth) => 'foo' + '[bar]'.repeat(depth);

describe('regression::GHSA-pmv8-rq9r-6j72 formDataToJSON depth limit', () => {
  it('should throw AxiosError when a field path exceeds the default depth limit', () => {
    assert.throws(
      () => formDataToJSON(fakeFormData([[deepKey(101), '123']])),
      (err) => err instanceof AxiosError &&
        err.code === AxiosError.ERR_FORM_DATA_DEPTH_EXCEEDED &&
        !(err instanceof RangeError)
    );
  });

  it('should throw AxiosError, not RangeError, for very deep field paths', () => {
    assert.throws(
      () => formDataToJSON(fakeFormData([[deepKey(20000), '123']])),
      (err) => err instanceof AxiosError &&
        err.code === AxiosError.ERR_FORM_DATA_DEPTH_EXCEEDED &&
        !(err instanceof RangeError)
    );
  });

  it('should still convert a field path at the depth limit', () => {
    let value = formDataToJSON(fakeFormData([[deepKey(100), '123']])).foo;

    for (let i = 0; i < 100; i++) {
      value = value.bar;
    }

    assert.strictEqual(value, '123');
  });

  it('should reject a deeply nested FormData sent as JSON before reaching the adapter', async () => {
    let adapterCalled = false;

    await assert.rejects(
      axios.post('http://example.invalid/', fakeFormData([[deepKey(20000), '1']]), {
        headers: {'Content-Type': 'application/json'},
        adapter: async () => {
          adapterCalled = true;
          throw new Error('adapter must not be reached');
        }
      }),
      (err) => err instanceof AxiosError && err.code === AxiosError.ERR_FORM_DATA_DEPTH_EXCEEDED
    );

    assert.strictEqual(adapterCalled, false);
  });
});
