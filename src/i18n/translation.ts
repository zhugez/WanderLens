import { siteConfig } from '../config'
import type I18nKey from './i18nKey'
import { en } from './languages/en'

export type Translation = {
  [K in I18nKey]: string
}

const defaultTranslation = en

export function i18n(key: I18nKey): string {
  return defaultTranslation[key] || key
}
