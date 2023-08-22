import { KeyManagementServiceClient } from '@google-cloud/kms'
import { Draft, produce } from 'immer'
import objectPath from 'object-path'
import { debug } from './debugger'
import type { DMMFModels } from './dmmf'
import { errors, warnings } from './errors'
import { hashString } from './hash'
import type { Configuration, MiddlewareParams } from './types'
import { visitInputTargetFields, visitOutputTargetFields } from './visitor'

export interface KeysConfiguration {
  client: KeyManagementServiceClient
}

const projectId = 'atemwegsliga-dev'
const locationId = 'global'
const keyRing = 'atemwegsliga-dev-ring'
const client = new KeyManagementServiceClient({
  projectId,
  credentials: {
    client_email: process.env.KMS_CLIENT_EMAIL,
    private_key: process.env.KMS_PRIVATE_KEY
  }
})

export async function configureKeys(
  config: Configuration
): Promise<KeysConfiguration> {
  const keyRingPath = client.keyRingPath(projectId, locationId, keyRing)
  const encryptionKey = await client.getCryptoKey({
    name: keyRingPath
  })

  if (!encryptionKey) {
    throw new Error(errors.noEncryptionKey)
  }

  return {
    client
  }
}

// --

export function encryptOnWrite<Models extends string, Actions extends string>(
  params: MiddlewareParams<Models, Actions>,
  models: DMMFModels,
  operation: string
) {
  debug.encryption('Clear-text input: %O', params)
  const encryptionErrors: string[] = []
  const mutatedParams = produce(
    params,
    (draft: Draft<MiddlewareParams<Models, Actions>>) => {
      visitInputTargetFields(
        draft,
        models,
        function encryptFieldValue({
          fieldConfig,
          value: clearText,
          path,
          model,
          field
        }) {
          const hashedPath = rewriteHashedFieldPath(
            path,
            field,
            fieldConfig.hash?.targetField ?? field + 'Hash'
          )
          if (hashedPath) {
            if (!fieldConfig.hash) {
              console.warn(warnings.whereConnectClauseNoHash(operation, path))
            } else {
              const hash = hashString(clearText, fieldConfig.hash)
              debug.encryption(
                `Swapping encrypted search of ${model}.${field} with hash search under ${fieldConfig.hash.targetField} (hash: ${hash})`
              )
              objectPath.del(draft.args, path)
              objectPath.set(draft.args, hashedPath, hash)
              return
            }
          }
          if (isOrderBy(path, field, clearText)) {
            // Remove unsupported orderBy clause on encrypted text
            // (makes no sense to sort ciphertext nor to encrypt 'asc' | 'desc')
            console.error(errors.orderByUnsupported(model, field))
            debug.encryption(
              `Removing orderBy clause on ${model}.${field} at path \`${path}: ${clearText}\``
            )
            objectPath.del(draft.args, path)
            return
          }
          if (!fieldConfig.encrypt) {
            return
          }
          try {
            const cipherText = client.encrypt({ plaintext: clearText })
            objectPath.set(draft.args, path, cipherText)
            debug.encryption(`Encrypted ${model}.${field} at path \`${path}\``)
            if (fieldConfig.hash) {
              const hash = hashString(clearText, fieldConfig.hash)
              const hashPath = rewriteWritePath(
                path,
                field,
                fieldConfig.hash.targetField
              )
              objectPath.set(draft.args, hashPath, hash)
              debug.encryption(
                `Added hash ${hash} of ${model}.${field} under ${fieldConfig.hash.targetField}`
              )
            }
          } catch (error) {
            encryptionErrors.push(
              errors.fieldEncryptionError(model, field, path, error)
            )
          }
        }
      )
    }
  )
  if (encryptionErrors.length > 0) {
    throw new Error(errors.encryptionErrorReport(operation, encryptionErrors))
  }
  debug.encryption('Encrypted input: %O', mutatedParams)
  return mutatedParams
}

export function decryptOnRead<Models extends string, Actions extends string>(
  params: MiddlewareParams<Models, Actions>,
  result: any,
  models: DMMFModels,
  operation: string
) {
  // Analyse the query to see if there's anything to decrypt.
  const model = models[params.model!]
  if (
    Object.keys(model.fields).length === 0 &&
    !params.args?.include &&
    !params.args?.select
  ) {
    // The queried model doesn't have any encrypted field,
    // and there are no included connections.
    // We can safely skip decryption for the returned data.
    // todo: Walk the include/select tree for a better decision.
    debug.decryption(
      `Skipping decryption: ${params.model} has no encrypted field and no connection was included`
    )
    return
  }

  debug.decryption('Raw result from database: %O', result)

  const decryptionErrors: string[] = []
  const fatalDecryptionErrors: string[] = []

  visitOutputTargetFields(
    params,
    result,
    models,
    function decryptFieldValue({
      fieldConfig,
      value: cipherText,
      path,
      model,
      field
    }) {
      try {
        const clearText = client.decrypt({ ciphertext: cipherText })
        objectPath.set(result, path, clearText)
        debug.decryption(`Decrypted ${model}.${field} at path \`${path}\``)
      } catch (error) {
        const message = errors.fieldDecryptionError(model, field, path, error)
        if (fieldConfig.strictDecryption) {
          fatalDecryptionErrors.push(message)
        } else {
          decryptionErrors.push(message)
        }
      }
    }
  )
  if (decryptionErrors.length > 0) {
    console.error(errors.decryptionErrorReport(operation, decryptionErrors))
  }
  if (fatalDecryptionErrors.length > 0) {
    throw new Error(
      errors.decryptionErrorReport(operation, fatalDecryptionErrors)
    )
  }
  debug.decryption('Decrypted result: %O', result)
}

function rewriteHashedFieldPath(
  path: string,
  field: string,
  hashField: string
) {
  const items = path.split('.').reverse()
  // Special case for `where field equals` clause
  if (items.includes('where') && items[1] === field && items[0] === 'equals') {
    items[1] = hashField
    return items.reverse().join('.')
  }
  const clauses = ['where', 'connect', 'cursor']
  for (const clause of clauses) {
    if (items.includes(clause) && items[0] === field) {
      items[0] = hashField
      return items.reverse().join('.')
    }
  }
  return null
}

function rewriteWritePath(path: string, field: string, hashField: string) {
  const items = path.split('.').reverse()
  if (items[0] === field) {
    items[0] = hashField
  } else if (items[0] === 'set' && items[1] === field) {
    items[1] = hashField
  }
  return items.reverse().join('.')
}

function isOrderBy(path: string, field: string, value: string) {
  const items = path.split('.').reverse()
  return (
    items.includes('orderBy') &&
    items[0] === field &&
    ['asc', 'desc'].includes(value.toLowerCase())
  )
}
