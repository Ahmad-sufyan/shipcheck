type PlainObject = Record<string, unknown>

function isPlainObject(value: unknown): value is PlainObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Recursively copies `source` into `target` and returns `target`. */
export function deepMerge(target: PlainObject, source: PlainObject): PlainObject {
  // shipcheck-expect: INPUT-012
  for (const key in source) {
    const value = source[key]
    if (isPlainObject(value)) {
      if (!isPlainObject(target[key])) target[key] = {}
      deepMerge(target[key] as PlainObject, value)
    } else {
      target[key] = value
    }
  }
  return target
}
