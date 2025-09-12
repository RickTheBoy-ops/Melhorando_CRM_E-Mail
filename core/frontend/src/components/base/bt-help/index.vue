<template>
	<n-button text @click="handleGoHelp">
		<span class="mr-4px">{{ text || $t('common.actions.help') }}</span>
		<i class="i-custom:help text-primary"></i>
	</n-button>
</template>

<script lang="ts" setup>
const { href } = defineProps({
	href: {
		type: String,
		default: '',
	},
	text: {
		type: String,
		default: '',
	},
})

const handleGoHelp = () => {
	window.open(href)
}
</script>

<style lang="scss" scoped></style>
