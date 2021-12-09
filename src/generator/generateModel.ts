import fs from 'node:fs/promises'
import path from 'node:path'
import type { DMMFModelDescriptor } from '../dmmf'

export interface GenerateModelArgs {
  modelName: string
  model: DMMFModelDescriptor
  prismaClientModule: string
  outputDir: string
}

export async function generateModel({
  modelName,
  model,
  prismaClientModule,
  outputDir
}: GenerateModelArgs) {
  const fields = Object.keys(model.fields)
  const interfaceName = modelName.slice(0, 1).toLowerCase() + modelName.slice(1)
  const content = `// This file was generated by prisma-field-encryption.

import type { PrismaClient, ${modelName} } from '${prismaClientModule}'
import { ProgressReportCallback, defaultProgressReport } from './index'

type Cursor = ${modelName}['${model.cursor}'] | undefined

export async function migrate(
  client: PrismaClient,
  reportProgress: ProgressReportCallback = defaultProgressReport
) {
  const totalCount = await client.${interfaceName}.count()
  if (totalCount === 0) {
    return
  }
  let cursor: Cursor = undefined
  let processed = 0
  while (true) {
    const tick = performance.now()
    const newCursor: Cursor = await migrateRecord(client, cursor)
    if (newCursor === cursor) {
      break // Reached the end
    }
    cursor = newCursor
    processed++
    const tock = performance.now()
    reportProgress({
      model: '${modelName}',
      processed,
      totalCount,
      performance: tock - tick
    })
  }
}

async function migrateRecord(client: PrismaClient, cursor: Cursor) {
  return await client.$transaction(async tx => {
    const record = await tx.${interfaceName}.findFirst({
      take: 1,
      skip: cursor === undefined ? undefined : 1,
      ...(cursor === undefined
        ? {}
        : {
            cursor: {
              ${model.cursor}: cursor
            }
          }),
      orderBy: {
        ${model.cursor}: 'asc'
      },
      select: {
        ${model.cursor}: true,
        ${fields.map(field => `${field}: true`).join(',\n        ')}
      }
    })
    if (!record) {
      return cursor
    }
    await tx.${interfaceName}.update({
      where: {
        ${model.cursor}: record.${model.cursor}
      },
      data: {
        ${fields.map(field => `${field}: record.${field}`).join(',\n        ')}
      }
    })
    return record.${model.cursor}
  })
}

/**
 * Internal model:
 * ${JSON.stringify(model, null, 2).split('\n').join('\n * ')}
 */
`
  const outputPath = path.join(outputDir, `${modelName}.ts`)
  return fs.writeFile(outputPath, content)
}
