import { createI18n } from 'vue-i18n'
import ptbr from './lang/pt-br.json'

const i18n = createI18n({
	legacy: false,
	globalInjection: true,
	locale: 'pt-br',
	fallbackLocale: 'pt-br',
	messages: {
		'pt-br': ptbr,
	},
})

// Método para garantir que o idioma seja sempre português do Brasil
export const setLanguage = () => {
	// Garantir que o idioma seja sempre português do Brasil
	i18n.global.locale.value = 'pt-br'
}

export default i18n
