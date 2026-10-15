type PlainObject = Record<string, unknown>

const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function isPlainObject(value: unknown): value is PlainObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Recursively copies own keys of `source` into `target`, skipping prototype-polluting keys. */
export function deepMerge(target: PlainObject, source: PlainObject): PlainObject {
  for (const key of Object.keys(source)) {
    if (BLOCKED_KEYS.has(key)) continue
    const value = source[key]
    if (isPlainObject(value)) {
      const current = Object.hasOwn(target, key) && isPlainObject(target[key]) ? (target[key] as PlainObject) : {}
      target[key] = deepMerge(current, value)
    } else {
      target[key] = value
    }
  }
  return target
}
