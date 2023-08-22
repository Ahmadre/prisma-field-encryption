import { configureKeys } from './encryption'
import { errors } from './errors'

describe('encryption', () => {
  describe('configureKeys', () => {
    test('No encryption key specified', () => {
      const run = () => configureKeys({})
      expect(run).toThrowError(errors.noEncryptionKey)
    })
  })
})
