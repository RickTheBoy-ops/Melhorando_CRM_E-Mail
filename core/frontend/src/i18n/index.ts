import { createI18n } from 'vue-i18n'
import en from './lang/en.json'
import zh from './lang/zh.json'
import ja from './lang/ja.json'
import pt from './lang/pt.json'

const i18n = createI18n({
	legacy: false,
	globalInjection: true,
	locale: 'pt',
	fallbackLocale: 'pt',
	messages: {
		en,
		zh,
		ja,
		pt,
	},
})

// Método para garantir que o idioma seja sempre português
export const setLanguage = () => {
	// Garantir que o idioma seja sempre português
	i18n.global.locale.value = 'pt'
}

export default i18n
