import Zemu from '@zondax/zemu'
// @ts-ignore
import SecretApp from 'ledger-secret-js'
import { DEFAULT_OPTIONS, DEVICE_MODELS, example_tx_str_execute } from './common'

// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'
import { fromHex } from 'secretjs'

jest.setTimeout(60000)

describe('Secret Network', function () {
  test.each(DEVICE_MODELS)('sign basic with extra fields', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new SecretApp(sim.getTransport())

      const path = [44, 529, 0, 0, 0]
      const tx = JSON.stringify(example_tx_str_execute)

      // get address / publickey
      const respPk = await app.getAddressAndPubKey(path, 'secret')
      expect(respPk.return_code).toEqual(0x9000)
      expect(respPk.error_message).toEqual('No errors')
      console.log(respPk)

      // tx encryption key
      const txKey = fromHex('4c99abfc82816e168ff59c4468fe222d7aa00bbc37cb8ec7b33698d6a9b6fb28')
        
      const request = app.signTransparent(path, new TextEncoder().encode(tx), txKey)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_secret_wasm_decrypt`)

      const resp = await request as any
      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = Uint8Array.from(hash.update(tx).digest())

      const signatureDER = resp.signature
      const signature = secp256k1.signatureImport(Uint8Array.from(signatureDER))

      const pk = Uint8Array.from(respPk.compressed_pk)

      const signatureOk = secp256k1.ecdsaVerify(signature, msgHash, pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})