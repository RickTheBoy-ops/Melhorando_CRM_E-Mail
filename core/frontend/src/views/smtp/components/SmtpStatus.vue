<template>
	<n-tag size="small" :bordered="false">
		<div class="status-icon" :class="value ? 'status-success' : 'status-error'"></div>
		<div class="status-text">{{ value ? $t('smtp.status.online') : $t('smtp.status.offline') }}</div>
	</n-tag>
</template>

<script lang="ts" setup>
defineProps({
	value: {
		type: Boolean,
		default: false,
	},
})
</script>

<style lang="scss" scoped>
.n-tag {
	padding: 6px 10px;
	border-radius: 16px;
	:deep(.n-tag__content) {
		display: flex;
		align-items: center;
		gap: 8px;
	}
	.status-icon {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		&.status-success {
			background-color: var(--color-primary-1);
		}
		&.status-error {
			background-color: var(--color-error-1);
		}
	}
	.status-text {
		font-weight: 500;
		white-space: nowrap;
	}
}
</style>
