import fs from 'node:fs/promises'
import path from 'node:path'
import type { DMMFModels } from '../dmmf'

export interface GenerateIndexArgs {
  models: DMMFModels
  prismaClientModule: string
  outputDir: string
  modelNamePad: number
}

export async function generateIndex({
  models,
  outputDir,
  modelNamePad,
  prismaClientModule
}: GenerateIndexArgs) {
  const modelImports = Object.keys(models).map(
    modelName =>
      `import { migrate as migrate${modelName} } from './${modelName}'`
  )
  const contents = `// This file was generated by prisma-field-encryption.

import type { PrismaClient } from '${prismaClientModule}'
${modelImports.join('\n')}

export interface ProgressReport {
  model: string
  processed: number
  totalCount: number
  performance: number
}

export type ProgressReportCallback = (
  progress: ProgressReport
) => void | Promise<void>

export const defaultProgressReport: ProgressReportCallback = ({
  model,
  totalCount,
  processed,
  performance
}) => {
  const length = totalCount.toString().length
  const pct = Math.round((100 * processed) / totalCount)
    .toString()
    .padStart(3)
  console.info(
    \`\${model.padEnd(${modelNamePad})} \${pct}% processed \${processed
      .toString()
      .padStart(length)} / \${totalCount} (took \${performance.toFixed(2)}ms)\`
  )
}

// --

export async function migrate(
  client: PrismaClient,
  reportProgress: ProgressReportCallback = defaultProgressReport
) {
  await Promise.all([
${Object.keys(models)
  .map(modelName => `    migrate${modelName}(client, reportProgress)`)
  .join(',\n')}
  ])
}
`
  const outputPath = path.join(outputDir, 'index.ts')
  return fs.writeFile(outputPath, contents)
}
