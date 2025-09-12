<template>
	<n-config-provider
		abstract
		inline-theme-disabled
		:theme="themeRef"
		:locale="locale"
		:date-locale="dateLocale"
		:theme-overrides="themeOverrides">
		<slot></slot>
	</n-config-provider>
</template>

<script lang="ts" setup>
import { storeToRefs } from 'pinia'
import { enUS, zhCN, jaJP, dateEnUS, dateZhCN, dateJaJP, darkTheme, createLocale } from 'naive-ui'
import { useGlobalStore, useThemeStore } from '@/store'

const globalStore = useGlobalStore()
const { lang } = storeToRefs(globalStore)

const themeStore = useThemeStore()
const { theme, themeOverrides } = storeToRefs(themeStore)

// Criando locale para português brasileiro
const ptBR = createLocale({
	name: 'pt-BR',
	global: {
		undo: 'Desfazer',
		redo: 'Refazer',
		confirm: 'Confirmar',
	},
	Popconfirm: {
		positiveText: 'Confirmar',
		negativeText: 'Cancelar',
	},
	Cascader: {
		placeholder: 'Selecionar',
		loading: 'Carregando',
		loadingRequiredMessage: (label) => `Carregue todos os filhos de ${label} antes de selecioná-lo`,
	},
	Time: {
		dateFormat: 'dd/MM/yyyy',
		dateTimeFormat: 'dd/MM/yyyy HH:mm:ss',
	},
	DatePicker: {
		yearFormat: 'yyyy',
		monthFormat: 'MMM',
		dayFormat: 'eeeeee',
		clear: 'Limpar',
		now: 'Agora',
		confirm: 'Confirmar',
		selectTime: 'Selecionar hora',
		selectDate: 'Selecionar data',
		datePlaceholder: 'Selecionar data',
		datetimePlaceholder: 'Selecionar data e hora',
		monthPlaceholder: 'Selecionar mês',
		yearPlaceholder: 'Selecionar ano',
		startDatePlaceholder: 'Data de início',
		endDatePlaceholder: 'Data de fim',
		startDatetimePlaceholder: 'Data e hora de início',
		endDatetimePlaceholder: 'Data e hora de fim',
		monthBeforeYear: true,
		firstDayOfWeek: 0,
		today: 'Hoje',
	},
	DataTable: {
		checkTableAll: 'Selecionar tudo',
		uncheckTableAll: 'Desmarcar tudo',
		confirm: 'Confirmar',
		clear: 'Limpar',
	},
	Transfer: {
		sourceTitle: 'Origem',
		targetTitle: 'Destino',
	},
	Empty: {
		description: 'Sem dados',
	},
	Select: {
		placeholder: 'Selecionar',
	},
	TimePicker: {
		placeholder: 'Selecionar hora',
		positiveText: 'OK',
		negativeText: 'Cancelar',
		now: 'Agora',
	},
	Pagination: {
		goto: 'Ir para',
		selectionSuffix: 'página',
	},
	DynamicTags: {
		add: 'Adicionar',
	},
	Log: {
		loading: 'Carregando',
	},
	Input: {
		placeholder: 'Digite',
	},
	InputNumber: {
		placeholder: 'Digite',
	},
	DynamicInput: {
		create: 'Criar',
	},
	ThemeEditor: {
		title: 'Editor de tema',
		clearAllVars: 'Limpar todas as variáveis',
		clearSearch: 'Limpar busca',
		filterCompName: 'Filtrar por nome de componente',
		filterVarName: 'Filtrar por nome de variável',
		import: 'Importar',
		export: 'Exportar',
		restore: 'Restaurar',
	},
}, enUS);

// Usando dateEnUS como fallback para datePtBR
const datePtBR = dateEnUS;

const langMap = {
	zh: {
		locale: zhCN,
		dateLocale: dateZhCN,
	},
	en: {
		locale: enUS,
		dateLocale: dateEnUS,
	},
	ja: {
		locale: jaJP,
		dateLocale: dateJaJP,
	},
	pt: {
		locale: ptBR,
		dateLocale: datePtBR,
	},
}

const themeRef = computed(() => {
	if (theme.value === 'dark') {
		return darkTheme
	}
	return null
})

const locale = computed(() => {
	// Garantir que sempre retorne um objeto válido, mesmo se o idioma não existir no mapa
	const langObj = langMap[lang.value as keyof typeof langMap] || langMap.pt
	return langObj.locale
})

const dateLocale = computed(() => {
	// Garantir que sempre retorne um objeto válido, mesmo se o idioma não existir no mapa
	const langObj = langMap[lang.value as keyof typeof langMap] || langMap.pt
	return langObj.dateLocale
})

// const themeOverrides: GlobalThemeOverrides = {
// 	common: {
// 		lineHeight: 'normal',
// 		fontSize: '12px',
// 		fontSizeSmall: '12px',
// 		fontSizeMedium: '12px',
// 		fontSizeLarge: '14px',
// 		borderRadius: '4px',
// 		primaryColor: getCssVar('--color-primary-1'),
// 		primaryColorHover: '#1D9534',
// 		successColor: '#20A53A',
// 		successColorHover: '#1D9534',
// 		warningColor: '#F0AD4E',
// 		warningColorHover: '#C6892E',
// 		errorColor: '#ef0808',
// 		errorColorHover: '#C9302C',
// 	},
// 	Layout: {
// 		color: '#f4f7fa',
// 		textColor: '#333',
// 		headerColor: 'rgba(244, 247, 250, 0.7)',
// 		headerTextColor: '#5b6b79',
// 	},
// 	Menu: {
// 		fontSize: '14px',
// 	},
// 	Form: {
// 		feedbackHeightMedium: '20px',
// 		feedbackHeightLarge: '22px',
// 		feedbackFontSizeMedium: '12px',
// 		feedbackFontSizeLarge: '12px',
// 		feedbackPadding: '2px 0 0',
// 		labelFontSizeLeftMedium: '12px',
// 		labelPaddingHorizontal: '0 20px 0 0',
// 		labelFontSizeTopMedium: '12px',
// 	},
// 	Dialog: {
// 		contentMargin: '16px 0',
// 	},
// 	Radio: {
// 		labelPadding: '0 16px 0 8px',
// 		buttonColorActive: '#20A53A',
// 		buttonTextColorActive: '#fff',
// 	},
// 	DataTable: {
// 		thPaddingMedium: '10px',
// 		tdPaddingMedium: '10px',
// 	},
// 	Breadcrumb: {
// 		fontSize: '14px',
// 	},
// }
</script>
