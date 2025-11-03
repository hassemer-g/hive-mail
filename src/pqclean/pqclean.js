const initObj = { exports: {} };
(function(module) {
'use strict';

module.exports.init = (algorithms, createWorker) => {
  const byName = (algorithm) => ({ properties: { name } }) => name === algorithm;

  const maxWorkers = (() => {
    if (typeof navigator === 'object' && navigator.hardwareConcurrency) {
      return navigator.hardwareConcurrency;
    } else if (typeof require === 'function') {
      const os = require('node:os');
      if (typeof os.availableParallelism === 'function') {
        return os.availableParallelism();
      } else {
        return os.cpus().length;
      }
    } else {
      return 2;
    }
  })();

  let nWorkers = 0;
  const idleWorkers = [];
  const queue = [];

  function markWorkerIdle(worker) {
    const next = queue.shift();
    if (next) {
      runInIdleWorker(worker, next.task, next.resolve, next.reject);
    } else {
      idleWorkers.push(worker);
      if (typeof worker.unref === 'function') {
        // In Node.js, do not explicitly terminate idle workers, but allow the
        // runtime to do so if no other threads have work left to do.
        worker.unref();
      } else if (idleWorkers.length === nWorkers) {
        // In runtimes such as deno, we need to manually manage the lifetime of
        // our worker threads to prevent them from keeping the process alive
        // after all other threads are done. To prevent that, if all workers are
        // idle, schedule a macrotask, which, when invoked, checks if all
        // workers are still idle and then terminates all of them.
        setTimeout(() => {
          if (idleWorkers.length === nWorkers) {
            nWorkers = 0;
            for (const worker of idleWorkers.splice(0)) {
              worker.terminate();
            }
          }
        }, 0);
      }
    }
  }

  function runInIdleWorker(worker, task, resolve, reject) {
    if (typeof worker.ref === 'function') worker.ref();
    const isEventTarget = typeof worker.addEventListener === 'function';
    worker[isEventTarget ? 'addEventListener' : 'once']('message', function onResponse(response) {
      isEventTarget && worker.removeEventListener('message', onResponse);
      markWorkerIdle(worker);
      response = response.data || response;
      if (response.memoryAllocationFailed) {
        reject(new Error('Memory allocation failed'));
      } else {
        resolve(response);
      }
    });
    worker.postMessage(task);
  }

  function runInWorker(task) {
    return new Promise((resolve, reject) => {
      const idleWorker = idleWorkers.shift();
      if (idleWorker !== undefined) {
        // There is a worker that is currently idle. Use it.
        runInIdleWorker(idleWorker, task, resolve, reject);
      } else {
        // No worker is idle right now, so add to the queue.
        const queueSize = queue.push({ task, resolve, reject });
        if (queueSize > nWorkers ** 2 && nWorkers < maxWorkers) {
          // There are too many tasks queued, spin up a new worker.
          nWorkers++;
          createWorker().then((newWorker) => {
            markWorkerIdle(newWorker);
          }, (err) => {
            if (!--nWorkers) {
              for (const { reject } of queue.splice(0)) {
                reject(err);
              }
            }
          });
        }
      }
    });
  }

  const internal = Symbol();

  class PQCleanKEMPublicKey {
    #algorithm;
    #material;

    constructor(name, key) {
      if (arguments.length === 1 && typeof name === 'object' && internal in name) {
        [this.#algorithm, this.#material] = name[internal];
        return;
      }

      if (arguments.length !== 2) {
        throw new TypeError('Wrong number of arguments');
      }

      if (typeof name !== 'string') {
        throw new TypeError('First argument must be a string');
      }

      if (key instanceof ArrayBuffer) {
        this.#material = key.slice(0);
      } else if (ArrayBuffer.isView(key)) {
        this.#material =
            key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength);
      } else {
        throw new TypeError('Second argument must be a BufferSource');
      }

      if ((this.#algorithm = algorithms.kem.find(byName(name))) == null) {
        throw new Error('No such implementation');
      }

      if (this.#material.byteLength !== this.#algorithm.properties.publicKeySize) {
        throw new Error('Invalid public key size');
      }
    }

    get algorithm() {
      return { ...this.#algorithm.properties };
    }

    export() {
      return this.#material.slice(0);
    }

    generateKey() {
      if (arguments.length !== 0) {
        throw new TypeError('Wrong number of arguments');
      }

      const { keySize, encryptedKeySize } = this.#algorithm.properties;
      return runInWorker({
        fn: this.#algorithm.functions.enc,
        inputs: [this.#material],
        outputs: [{ type: 'ArrayBuffer', byteLength: encryptedKeySize },
                  { type: 'ArrayBuffer', byteLength: keySize }]
      }).then(({ result, outputs }) => {
        if (result !== 0) {
          return Promise.reject(new Error('Encapsulation failed'));
        } else {
          return Promise.resolve({ key: outputs[1], encryptedKey: outputs[0] });
        }
      });
    }
  }

  class PQCleanKEMPrivateKey {
    #algorithm;
    #material;

    constructor(name, key) {
      if (arguments.length === 1 && typeof name === 'object' && internal in name) {
        [this.#algorithm, this.#material] = name[internal];
        return;
      }

      if (arguments.length !== 2) {
        throw new TypeError('Wrong number of arguments');
      }

      if (typeof name !== 'string') {
        throw new TypeError('First argument must be a string');
      }

      if (key instanceof ArrayBuffer) {
        this.#material = key.slice(0);
      } else if (ArrayBuffer.isView(key)) {
        this.#material =
            key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength);
      } else {
        throw new TypeError('Second argument must be a BufferSource');
      }

      if ((this.#algorithm = algorithms.kem.find(byName(name))) == null) {
        throw new Error('No such implementation');
      }

      if (this.#material.byteLength !== this.#algorithm.properties.privateKeySize) {
        throw new Error('Invalid private key size');
      }
    }

    get algorithm() {
      return { ...this.#algorithm.properties };
    }

    export() {
      return this.#material.slice(0);
    }

    decryptKey(encryptedKey) {
      if (arguments.length !== 1) {
        throw new TypeError('Wrong number of arguments');
      }

      let encryptedKeyArrayBuffer;
      if (encryptedKey instanceof ArrayBuffer) {
        encryptedKeyArrayBuffer = encryptedKey.slice();
      } else if (ArrayBuffer.isView(encryptedKey)) {
        encryptedKeyArrayBuffer = encryptedKey.buffer.slice(
            encryptedKey.byteOffset, encryptedKey.byteOffset + encryptedKey.byteLength);
      } else {
        throw new TypeError('First argument must be a BufferSource');
      }

      const { keySize, encryptedKeySize } = this.#algorithm.properties;
      if (encryptedKeyArrayBuffer.byteLength !== encryptedKeySize) {
        throw new Error('Invalid ciphertext size');
      }

      return runInWorker({
        fn: this.#algorithm.functions.dec,
        inputs: [encryptedKeyArrayBuffer, this.#material],
        outputs: [{ type: 'ArrayBuffer', byteLength: keySize }]
      }).then(({ result, outputs }) => {
        if (result !== 0) {
          return Promise.reject(new Error('Decryption failed'));
        } else {
          return Promise.resolve(outputs[0]);
        }
      });
    }
  }

  function generateKEMKeyPair(name) {
    if (arguments.length !== 1) {
      throw new TypeError('Wrong number of arguments');
    }

    if (typeof name !== 'string') {
      throw new TypeError('First argument must be a string');
    }

    const algorithm = algorithms.kem.find(byName(name));
    if (algorithm == null) {
      throw new Error('No such implementation');
    }

    const { publicKeySize, privateKeySize } = algorithm.properties;

    return runInWorker({
      fn: algorithm.functions.keypair,
      inputs: [],
      outputs: [{ type: 'ArrayBuffer', byteLength: publicKeySize},
                { type: 'ArrayBuffer', byteLength: privateKeySize } ]
    }).then(({ result, outputs }) => {
      if (result !== 0) {
        return Promise.reject(new Error('Failed to generate keypair'));
      } else {
        return Promise.resolve({
          publicKey: new PQCleanKEMPublicKey({ [internal]: [algorithm, outputs[0]] }),
          privateKey: new PQCleanKEMPrivateKey({ [internal]: [algorithm, outputs[1]] })
        });
      }
    });
  }

  class PQCleanSignPublicKey {
    #algorithm;
    #material;

    constructor(name, key) {
      if (arguments.length === 1 && typeof name === 'object' && internal in name) {
        [this.#algorithm, this.#material] = name[internal];
        return;
      }

      if (arguments.length !== 2) {
        throw new TypeError('Wrong number of arguments');
      }

      if (typeof name !== 'string') {
        throw new TypeError('First argument must be a string');
      }

      if (key instanceof ArrayBuffer) {
        this.#material = key.slice(0);
      } else if (ArrayBuffer.isView(key)) {
        this.#material =
            key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength);
      } else {
        throw new TypeError('Second argument must be a BufferSource');
      }

      if ((this.#algorithm = algorithms.sign.find(byName(name))) == null) {
        throw new Error('No such implementation');
      }

      if (this.#material.byteLength !== this.#algorithm.properties.publicKeySize) {
        throw new Error('Invalid public key size');
      }
    }

    get algorithm() {
      return { ...this.#algorithm.properties };
    }

    export() {
      return this.#material.slice(0);
    }

    verify(message, signature) {
      if (arguments.length !== 2) {
        throw new TypeError('Wrong number of arguments');
      }

      let messageArrayBuffer;
      if (message instanceof ArrayBuffer) {
        messageArrayBuffer = message.slice();
      } else if (ArrayBuffer.isView(message)) {
        messageArrayBuffer = message.buffer.slice(
            message.byteOffset, message.byteOffset + message.byteLength);
      } else {
        throw new TypeError('First argument must be a BufferSource');
      }

      let signatureArrayBuffer;
      if (signature instanceof ArrayBuffer) {
        signatureArrayBuffer = signature.slice();
      } else if (ArrayBuffer.isView(signature)) {
        signatureArrayBuffer = signature.buffer.slice(
            signature.byteOffset, signature.byteOffset + signature.byteLength);
      } else {
        throw new TypeError('Second argument must be a BufferSource');
      }

      const { signatureSize: maxSignatureSize } = this.#algorithm.properties;
      if (signatureArrayBuffer.byteLength > maxSignatureSize) {
        throw new Error('Invalid signature size');
      }

      return runInWorker({
        fn: this.#algorithm.functions.verify,
        inputs: [
          signatureArrayBuffer, signatureArrayBuffer.byteLength,
          messageArrayBuffer, messageArrayBuffer.byteLength,
          this.#material
        ],
        outputs: []
      }).then(({ result }) => {
        // TODO: can we distinguish verification errors from other internal errors?
        return Promise.resolve(result === 0);
      })
    }

    open(signedMessage) {
      if (arguments.length !== 1) {
        throw new TypeError('Wrong number of arguments');
      }

      let signedMessageArrayBuffer;
      if (signedMessage instanceof ArrayBuffer) {
        signedMessageArrayBuffer = signedMessage.slice();
      } else if (ArrayBuffer.isView(signedMessage)) {
        signedMessageArrayBuffer = signedMessage.buffer.slice(
            signedMessage.byteOffset,
            signedMessage.byteOffset + signedMessage.byteLength);
      } else {
        throw new TypeError('First argument must be a BufferSource');
      }

      const messageSize = signedMessageArrayBuffer.byteLength;

      return runInWorker({
        fn: this.#algorithm.functions.open,
        inputs: [signedMessageArrayBuffer, messageSize, this.#material],
        outputs: [{ type: 'ArrayBuffer', byteLength: messageSize },
                  { type: 'u32', init: messageSize }]
      }).then(({ result, outputs }) => {
        if (result !== 0) {
          return Promise.reject(new Error('Open operation failed'));
        } else {
          // TODO: avoid copying here by somehow getting the properly sized
          // ArrayBuffer from the worker directly.
          const actualSize = outputs[1];
          return Promise.resolve(outputs[0].slice(0, actualSize));
        }
      });
    }
  }

  class PQCleanSignPrivateKey {
    #algorithm;
    #material;

    constructor(name, key) {
      if (arguments.length === 1 && typeof name === 'object' && internal in name) {
        [this.#algorithm, this.#material] = name[internal];
        return;
      }

      if (arguments.length !== 2) {
        throw new TypeError('Wrong number of arguments');
      }

      if (typeof name !== 'string') {
        throw new TypeError('First argument must be a string');
      }

      if (key instanceof ArrayBuffer) {
        this.#material = key.slice(0);
      } else if (ArrayBuffer.isView(key)) {
        this.#material =
            key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength);
      } else {
        throw new TypeError('Second argument must be a BufferSource');
      }

      if ((this.#algorithm = algorithms.sign.find(byName(name))) == null) {
        throw new Error('No such implementation');
      }

      if (this.#material.byteLength !== this.#algorithm.properties.privateKeySize) {
        throw new Error('Invalid private key size');
      }
    }

    get algorithm() {
      return { ...this.#algorithm.properties };
    }

    export() {
      return this.#material.slice(0);
    }

    sign(message) {
      if (arguments.length !== 1) {
        throw new TypeError('Wrong number of arguments');
      }

      let messageArrayBuffer;
      if (message instanceof ArrayBuffer) {
        messageArrayBuffer = message.slice();
      } else if (ArrayBuffer.isView(message)) {
        messageArrayBuffer = message.buffer.slice(
            message.byteOffset, message.byteOffset + message.byteLength);
      } else {
        throw new TypeError('First argument must be a BufferSource');
      }

      const { signatureSize } = this.#algorithm.properties;
      const messageSize = messageArrayBuffer.byteLength;

      return runInWorker({
        fn: this.#algorithm.functions.signature,
        inputs: [messageArrayBuffer, messageSize, this.#material],
        outputs: [{ type: 'ArrayBuffer', byteLength: signatureSize },
                  { type: 'u32', init: signatureSize }]
      }).then(({ result, outputs }) => {
        if (result !== 0) {
          return Promise.reject(new Error('Sign operation failed'));
        } else {
          // TODO: avoid copying here by somehow getting the properly sized
          // ArrayBuffer from the worker directly.
          const actualSize = outputs[1];
          if (actualSize > signatureSize) {
            return Promise.reject(
                new Error(`Actual signature size (${actualSize}) exceeds maximum size (${signatureSize}).`));
          }
          return Promise.resolve(outputs[0].slice(0, actualSize));
        }
      });
    }

    signEmbed(message) {
      if (arguments.length !== 1) {
        throw new TypeError('Wrong number of arguments');
      }

      let messageArrayBuffer;
      if (message instanceof ArrayBuffer) {
        messageArrayBuffer = message.slice();
      } else if (ArrayBuffer.isView(message)) {
        messageArrayBuffer = message.buffer.slice(
            message.byteOffset, message.byteOffset + message.byteLength);
      } else {
        throw new TypeError('First argument must be a BufferSource');
      }

      const { signatureSize } = this.#algorithm.properties;
      const messageSize = messageArrayBuffer.byteLength;
      const signedMessageSize = messageSize + signatureSize;

      return runInWorker({
        fn: this.#algorithm.functions.sign,
        inputs: [messageArrayBuffer, messageSize, this.#material],
        outputs: [{ type: 'ArrayBuffer', byteLength: signedMessageSize },
                  { type: 'u32', init: signedMessageSize }]
      }).then(({ result, outputs }) => {
        if (result !== 0) {
          return Promise.reject(new Error('Sign operation failed'));
        } else {
          // TODO: avoid copying here by somehow getting the properly sized
          // ArrayBuffer from the worker directly.
          const actualSize = outputs[1];
          return Promise.resolve(outputs[0].slice(0, actualSize));
        }
      });
    }
  }

  function generateSignKeyPair(name) {
    if (arguments.length !== 1) {
      throw new TypeError('Wrong number of arguments');
    }

    if (typeof name !== 'string') {
      throw new TypeError('First argument must be a string');
    }

    const algorithm = algorithms.sign.find(byName(name));
    if (algorithm == null) {
      throw new Error('No such implementation');
    }

    const { publicKeySize, privateKeySize } = algorithm.properties;

    return runInWorker({
      fn: algorithm.functions.keypair,
      inputs: [],
      outputs: [{ type: 'ArrayBuffer', byteLength: publicKeySize},
                { type: 'ArrayBuffer', byteLength: privateKeySize } ]
    }).then(({ result, outputs }) => {
      if (result !== 0) {
        return Promise.reject(new Error('Failed to generate keypair'));
      } else {
        return Promise.resolve({
          publicKey: new PQCleanSignPublicKey({ [internal]: [algorithm, outputs[0]] }),
          privateKey: new PQCleanSignPrivateKey({ [internal]: [algorithm, outputs[1]] })
        });
      }
    });
  }

  return {
    kem: Object.defineProperties({}, {
      PublicKey: { value: PQCleanKEMPublicKey },
      PrivateKey: { value: PQCleanKEMPrivateKey },
      generateKeyPair: { value: generateKEMKeyPair },
      supportedAlgorithms: {
        value: algorithms.kem.map(({ properties }) => ({ ...properties }))
      }
    }),
    sign: Object.defineProperties({}, {
      PublicKey: { value: PQCleanSignPublicKey },
      PrivateKey: { value: PQCleanSignPrivateKey },
      generateKeyPair: { value: generateSignKeyPair },
      supportedAlgorithms: {
        value: algorithms.sign.map(({ properties }) => ({ ...properties }))
      }
    })
  };
};

})(initObj);
export default initObj.exports.init({"kem":[{"properties":{"name":"hqc-128","description":"HQC-128","publicKeySize":2249,"privateKeySize":2305,"keySize":64,"encryptedKeySize":4433},"functions":{"keypair":"PQCLEAN_HQC128_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_HQC128_CLEAN_crypto_kem_enc","dec":"PQCLEAN_HQC128_CLEAN_crypto_kem_dec"}},{"properties":{"name":"hqc-192","description":"HQC-192","publicKeySize":4522,"privateKeySize":4586,"keySize":64,"encryptedKeySize":8978},"functions":{"keypair":"PQCLEAN_HQC192_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_HQC192_CLEAN_crypto_kem_enc","dec":"PQCLEAN_HQC192_CLEAN_crypto_kem_dec"}},{"properties":{"name":"hqc-256","description":"HQC-256","publicKeySize":7245,"privateKeySize":7317,"keySize":64,"encryptedKeySize":14421},"functions":{"keypair":"PQCLEAN_HQC256_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_HQC256_CLEAN_crypto_kem_enc","dec":"PQCLEAN_HQC256_CLEAN_crypto_kem_dec"}},{"properties":{"name":"mceliece348864","description":"Classic McEliece 348864","publicKeySize":261120,"privateKeySize":6492,"keySize":32,"encryptedKeySize":96},"functions":{"keypair":"PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec"}},{"properties":{"name":"mceliece348864f","description":"Classic McEliece 348864","publicKeySize":261120,"privateKeySize":6492,"keySize":32,"encryptedKeySize":96},"functions":{"keypair":"PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec"}},{"properties":{"name":"mceliece460896","description":"Classic McEliece 460896","publicKeySize":524160,"privateKeySize":13608,"keySize":32,"encryptedKeySize":156},"functions":{"keypair":"PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec"}},{"properties":{"name":"mceliece460896f","description":"Classic McEliece 460896","publicKeySize":524160,"privateKeySize":13608,"keySize":32,"encryptedKeySize":156},"functions":{"keypair":"PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_dec"}},{"properties":{"name":"mceliece6688128","description":"Classic McEliece 6688128","publicKeySize":1044992,"privateKeySize":13932,"keySize":32,"encryptedKeySize":208},"functions":{"keypair":"PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec"}},{"properties":{"name":"mceliece6688128f","description":"Classic McEliece 6688128","publicKeySize":1044992,"privateKeySize":13932,"keySize":32,"encryptedKeySize":208},"functions":{"keypair":"PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec"}},{"properties":{"name":"mceliece6960119","description":"Classic McEliece 6960119","publicKeySize":1047319,"privateKeySize":13948,"keySize":32,"encryptedKeySize":194},"functions":{"keypair":"PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec"}},{"properties":{"name":"mceliece6960119f","description":"Classic McEliece 6960119","publicKeySize":1047319,"privateKeySize":13948,"keySize":32,"encryptedKeySize":194},"functions":{"keypair":"PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_dec"}},{"properties":{"name":"mceliece8192128","description":"Classic McEliece 8192128","publicKeySize":1357824,"privateKeySize":14120,"keySize":32,"encryptedKeySize":208},"functions":{"keypair":"PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec"}},{"properties":{"name":"mceliece8192128f","description":"Classic McEliece 8192128","publicKeySize":1357824,"privateKeySize":14120,"keySize":32,"encryptedKeySize":208},"functions":{"keypair":"PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec"}},{"properties":{"name":"ml-kem-1024","description":"ML-KEM-1024","publicKeySize":1568,"privateKeySize":3168,"keySize":32,"encryptedKeySize":1568},"functions":{"keypair":"PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec"}},{"properties":{"name":"ml-kem-512","description":"ML-KEM-512","publicKeySize":800,"privateKeySize":1632,"keySize":32,"encryptedKeySize":768},"functions":{"keypair":"PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec"}},{"properties":{"name":"ml-kem-768","description":"ML-KEM-768","publicKeySize":1184,"privateKeySize":2400,"keySize":32,"encryptedKeySize":1088},"functions":{"keypair":"PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair","enc":"PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc","dec":"PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec"}}],"sign":[{"properties":{"name":"falcon-1024","description":"Falcon-1024","publicKeySize":1793,"privateKeySize":2305,"signatureSize":1462},"functions":{"keypair":"PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature","sign":"PQCLEAN_FALCON1024_CLEAN_crypto_sign","verify":"PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify","open":"PQCLEAN_FALCON1024_CLEAN_crypto_sign_open"}},{"properties":{"name":"falcon-512","description":"Falcon-512","publicKeySize":897,"privateKeySize":1281,"signatureSize":752},"functions":{"keypair":"PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_FALCON512_CLEAN_crypto_sign_signature","sign":"PQCLEAN_FALCON512_CLEAN_crypto_sign","verify":"PQCLEAN_FALCON512_CLEAN_crypto_sign_verify","open":"PQCLEAN_FALCON512_CLEAN_crypto_sign_open"}},{"properties":{"name":"falcon-padded-1024","description":"Falcon-padded-1024","publicKeySize":1793,"privateKeySize":2305,"signatureSize":1280},"functions":{"keypair":"PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature","sign":"PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign","verify":"PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify","open":"PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_open"}},{"properties":{"name":"falcon-padded-512","description":"Falcon-padded-512","publicKeySize":897,"privateKeySize":1281,"signatureSize":666},"functions":{"keypair":"PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature","sign":"PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign","verify":"PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify","open":"PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_open"}},{"properties":{"name":"ml-dsa-44","description":"ML-DSA-44","publicKeySize":1312,"privateKeySize":2560,"signatureSize":2420},"functions":{"keypair":"PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature","sign":"PQCLEAN_MLDSA44_CLEAN_crypto_sign","verify":"PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify","open":"PQCLEAN_MLDSA44_CLEAN_crypto_sign_open"}},{"properties":{"name":"ml-dsa-65","description":"ML-DSA-65","publicKeySize":1952,"privateKeySize":4032,"signatureSize":3309},"functions":{"keypair":"PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature","sign":"PQCLEAN_MLDSA65_CLEAN_crypto_sign","verify":"PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify","open":"PQCLEAN_MLDSA65_CLEAN_crypto_sign_open"}},{"properties":{"name":"ml-dsa-87","description":"ML-DSA-87","publicKeySize":2592,"privateKeySize":4896,"signatureSize":4627},"functions":{"keypair":"PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature","sign":"PQCLEAN_MLDSA87_CLEAN_crypto_sign","verify":"PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify","open":"PQCLEAN_MLDSA87_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-sha2-128f-simple","description":"SPHINCS+-sha2-128f-simple","publicKeySize":32,"privateKeySize":64,"signatureSize":17088},"functions":{"keypair":"PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-sha2-128s-simple","description":"SPHINCS+-sha2-128s-simple","publicKeySize":32,"privateKeySize":64,"signatureSize":7856},"functions":{"keypair":"PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-sha2-192f-simple","description":"SPHINCS+-sha2-192f-simple","publicKeySize":48,"privateKeySize":96,"signatureSize":35664},"functions":{"keypair":"PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-sha2-192s-simple","description":"SPHINCS+-sha2-192s-simple","publicKeySize":48,"privateKeySize":96,"signatureSize":16224},"functions":{"keypair":"PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-sha2-256f-simple","description":"SPHINCS+-sha2-256f-simple","publicKeySize":64,"privateKeySize":128,"signatureSize":49856},"functions":{"keypair":"PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-sha2-256s-simple","description":"SPHINCS+-sha2-256s-simple","publicKeySize":64,"privateKeySize":128,"signatureSize":29792},"functions":{"keypair":"PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-shake-128f-simple","description":"SPHINCS+-shake-128f-simple","publicKeySize":32,"privateKeySize":64,"signatureSize":17088},"functions":{"keypair":"PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-shake-128s-simple","description":"SPHINCS+-shake-128s-simple","publicKeySize":32,"privateKeySize":64,"signatureSize":7856},"functions":{"keypair":"PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-shake-192f-simple","description":"SPHINCS+-shake-192f-simple","publicKeySize":48,"privateKeySize":96,"signatureSize":35664},"functions":{"keypair":"PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-shake-192s-simple","description":"SPHINCS+-shake-192s-simple","publicKeySize":48,"privateKeySize":96,"signatureSize":16224},"functions":{"keypair":"PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-shake-256f-simple","description":"SPHINCS+-shake-256f-simple","publicKeySize":64,"privateKeySize":128,"signatureSize":49856},"functions":{"keypair":"PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_open"}},{"properties":{"name":"sphincs-shake-256s-simple","description":"SPHINCS+-shake-256s-simple","publicKeySize":64,"privateKeySize":128,"signatureSize":29792},"functions":{"keypair":"PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair","signature":"PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature","sign":"PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign","verify":"PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify","open":"PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_open"}}]}, () => {
  return fetch(new URL('pqclean.wasm', import.meta.url)).then((wasmResponse) => {
    return WebAssembly.compileStreaming(wasmResponse);
  }).then((wasmModule) => {
    const worker = new Worker('data:text/javascript,%27use%20strict%27%3B%0Aself.addEventListener(%27message%27%2C%20function%20startWorker(initMessage)%20%7B%0A%20%20self.removeEventListener(%27message%27%2C%20startWorker)%3B%0A%20%20const%20wasmModule%20%3D%20initMessage.data%3B%0A%20%20(()%20%3D%3E%20%7B%27use%20strict%27%3B%0A%0Aconst%20randomBytes%20%3D%20(typeof%20crypto%20%3D%3D%3D%20%27object%27%20%26%26%20crypto.getRandomValues.bind(crypto))%20%7C%7C%20require(%27node%3Acrypto%27).randomFillSync%3B%0A%0Aconst%20isWebWorker%20%3D%20typeof%20WorkerGlobalScope%20!%3D%3D%20%27undefined%27%20%26%26%20self%20instanceof%20WorkerGlobalScope%3B%0Aconst%20parentPort%20%3D%20isWebWorker%20%3F%20self%20%3A%20require(%27node%3Aworker_threads%27).parentPort%3B%0A%0Aconst%20instance%20%3D%20new%20WebAssembly.Instance(typeof%20wasmModule%20%3D%3D%3D%20%27object%27%20%3F%20wasmModule%20%3A%20require(%27node%3Aworker_threads%27).workerData.wasmModule%2C%20%7B%0A%20%20env%3A%20%7B%0A%20%20%20%20PQCLEAN_randombytes(ptr%2C%20nBytes)%20%7B%0A%20%20%20%20%20%20randomBytes(new%20Uint8Array(instance.exports.memory.buffer%2C%20ptr%2C%20nBytes))%3B%0A%20%20%20%20%7D%0A%20%20%7D%2C%0A%20%20wasi_snapshot_preview1%3A%20%7B%0A%20%20%20%20proc_exit()%20%7B%0A%20%20%20%20%20%20throw%20new%20Error(%60WebAssembly%20code%20requested%20exit%20through%20WASI%20(%24%7B%5B...arguments%5D%7D)%60)%3B%0A%20%20%20%20%7D%0A%20%20%7D%0A%7D)%3B%0A%0Aconst%20store%20%3D%20(ptr%2C%20bytes)%20%3D%3E%20new%20Uint8Array(instance.exports.memory.buffer).set(bytes%2C%20ptr)%3B%0Aconst%20loadSlice%20%3D%20(ptr%2C%20size)%20%3D%3E%20instance.exports.memory.buffer.slice(ptr%2C%20ptr%20%2B%20size)%3B%0Aconst%20storeU32%20%3D%20(ptr%2C%20value)%20%3D%3E%20new%20DataView(instance.exports.memory.buffer).setUint32(ptr%2C%20value%2C%20true)%3B%0Aconst%20loadU32%20%3D%20(ptr)%20%3D%3E%20new%20DataView(instance.exports.memory.buffer).getUint32(ptr%2C%20true)%3B%0A%0AparentPort.addEventListener(%27message%27%2C%20(event)%20%3D%3E%20%7B%0A%20%20const%20%7B%20fn%2C%20outputs%2C%20inputs%20%7D%20%3D%20event.data%3B%0A%20%20let%20alloc%20%3D%200%3B%0A%20%20for%20(const%20o%20of%20outputs)%20%7B%0A%20%20%20%20if%20(o.type%20%3D%3D%3D%20%27u32%27)%20alloc%20%2B%3D%204%3B%0A%20%20%20%20else%20alloc%20%2B%3D%20o.byteLength%3B%0A%20%20%7D%0A%20%20for%20(const%20i%20of%20inputs)%20%7B%0A%20%20%20%20if%20(typeof%20i%20!%3D%3D%20%27number%27)%20%7B%0A%20%20%20%20%20%20alloc%20%2B%3D%20i.byteLength%3B%0A%20%20%20%20%7D%0A%20%20%7D%0A%0A%20%20const%20ptr%20%3D%20instance.exports.malloc(alloc)%3B%0A%20%20if%20(ptr%20%3D%3D%3D%200)%20%7B%0A%20%20%20%20parentPort.postMessage(%7B%20memoryAllocationFailed%3A%20true%20%7D)%3B%0A%20%20%20%20return%3B%0A%20%20%7D%0A%0A%20%20try%20%7B%0A%20%20%20%20let%20offset%20%3D%20ptr%3B%0A%20%20%20%20const%20outputArgs%20%3D%20outputs.map((output)%20%3D%3E%20%7B%0A%20%20%20%20%20%20if%20(output.type%20%3D%3D%3D%20%27u32%27)%20%7B%0A%20%20%20%20%20%20%20%20const%20%7B%20init%20%7D%20%3D%20output%3B%0A%20%20%20%20%20%20%20%20storeU32(offset%2C%20init)%3B%0A%20%20%20%20%20%20%20%20return%20(offset%20%2B%3D%204)%20-%204%3B%0A%20%20%20%20%20%20%7D%20else%20if%20(output.type%20%3D%3D%3D%20%27ArrayBuffer%27)%20%7B%0A%20%20%20%20%20%20%20%20const%20%7B%20byteLength%20%7D%20%3D%20output%3B%0A%20%20%20%20%20%20%20%20return%20(offset%20%2B%3D%20byteLength)%20-%20byteLength%3B%0A%20%20%20%20%20%20%7D%0A%20%20%20%20%7D)%3B%0A%20%20%20%20const%20inputArgs%20%3D%20inputs.map((input)%20%3D%3E%20%7B%0A%20%20%20%20%20%20if%20(typeof%20input%20%3D%3D%3D%20%27number%27)%20%7B%0A%20%20%20%20%20%20%20%20return%20input%3B%0A%20%20%20%20%20%20%7D%20else%20%7B%0A%20%20%20%20%20%20%20%20store(offset%2C%20new%20Uint8Array(input))%3B%0A%20%20%20%20%20%20%20%20return%20(offset%20%2B%3D%20input.byteLength)%20-%20input.byteLength%3B%0A%20%20%20%20%20%20%7D%0A%20%20%20%20%7D)%3B%0A%0A%20%20%20%20const%20result%20%3D%20instance.exports%5Bfn%5D(...outputArgs%2C%20...inputArgs)%3B%0A%20%20%20%20const%20outputValues%20%3D%20outputs.map((output%2C%20i)%20%3D%3E%20%7B%0A%20%20%20%20%20%20const%20offset%20%3D%20outputArgs%5Bi%5D%3B%0A%20%20%20%20%20%20if%20(output.type%20%3D%3D%3D%20%27u32%27)%20%7B%0A%20%20%20%20%20%20%20%20return%20loadU32(offset)%3B%0A%20%20%20%20%20%20%7D%20else%20if%20(output.type%20%3D%3D%3D%20%27ArrayBuffer%27)%20%7B%0A%20%20%20%20%20%20%20%20const%20%7B%20byteLength%20%7D%20%3D%20output%3B%0A%20%20%20%20%20%20%20%20return%20loadSlice(offset%2C%20byteLength)%3B%0A%20%20%20%20%20%20%7D%0A%20%20%20%20%7D)%3B%0A%0A%20%20%20%20parentPort.postMessage(%7B%20result%2C%20outputs%3A%20outputValues%20%7D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20outputValues.filter((v)%20%3D%3E%20v%20instanceof%20ArrayBuffer))%3B%0A%20%20%7D%20finally%20%7B%0A%20%20%20%20instance.exports.free(ptr)%3B%0A%20%20%7D%0A%7D)%3B%0A%7D)()%3B%0A%7D)%3B', {
      type: 'module'
    });
    worker.postMessage(wasmModule);
    return worker;
  });
});
