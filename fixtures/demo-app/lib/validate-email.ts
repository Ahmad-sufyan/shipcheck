// shipcheck-expect: INPUT-011
const EMAIL_PATTERN = /^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/

export function isValidEmail(value: string): boolean {
  return EMAIL_PATTERN.test(value)
}
