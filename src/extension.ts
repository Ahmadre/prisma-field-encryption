import { Prisma } from '@prisma/client/extension'
import { debug } from './debugger'
import { analyseDMMF } from './dmmf'
import { configureKeys, decryptOnRead, encryptOnWrite } from './encryption'
import { Configuration, MiddlewareParams } from './types'

export function fieldEncryptionExtension<
  Models extends string = any,
  Actions extends string = any
>(config: Configuration = {}) {
  configureKeys(config).then(_ => debug.setup('--- initialized keys ---'))
  const models = analyseDMMF(
    config.dmmf ?? require('@prisma/client').Prisma.dmmf
  )
  debug.setup('Models: %O', models)

  return Prisma.defineExtension({
    name: 'prisma-field-encryption',
    query: {
      $allModels: {
        async $allOperations({ model, operation, args, query }) {
          if (!model) {
            // Unsupported operation
            debug.runtime(
              'Unsupported operation %s (missing model): %O',
              operation,
              args
            )
            return await query(args)
          }
          const params: MiddlewareParams<Models, Actions> = {
            args,
            model: model as Models,
            action: operation as Actions,
            dataPath: [],
            runInTransaction: false
          }
          const encryptedParams = encryptOnWrite(params, models, operation)
          let result = await query(encryptedParams.args)
          decryptOnRead(encryptedParams, result, models, operation)
          return result
        }
      }
    }
  })
}
