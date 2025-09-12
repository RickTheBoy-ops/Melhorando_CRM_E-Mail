<template>
	<bt-config-provider>
		<router-view></router-view>
	</bt-config-provider>
</template>

<script lang="ts" setup>
import { useThemeStore } from './store'

const themeStore = useThemeStore()

// 监听主题变化并应用到文档
watch(
	() => themeStore.theme,
	() => {
		themeStore.changeTheme()
	},
	{
		immediate: true,
	}
)
</script>
