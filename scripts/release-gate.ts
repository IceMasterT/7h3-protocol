import { spawnSync } from 'node:child_process'

const commands: Array<[string, string[]]> = [
  ['npm', ['run', 'policy:validate']],
  ['npm', ['run', 'test']],
  ['npm', ['run', 'build:aip']],
  ['npm', ['run', 'lint']],
  ['npm', ['run', 'bench:wire:quick']],
  ['npm', ['run', 'bench:openloop:adaptive:ci']],
]

for (const [command, args] of commands) {
  console.log(`\n$ ${command} ${args.join(' ')}`)
  const result = spawnSync(command, args, { stdio: 'inherit', shell: false })
  if (result.status !== 0) {
    process.exitCode = result.status ?? 1
    break
  }
}
