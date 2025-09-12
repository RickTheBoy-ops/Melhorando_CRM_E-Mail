<template>
	<n-empty>
		<template #default>
			<div class="leading-22px text-13px text-desc text-center">
				<i18n-t tag="span" scope="global" keypath="components.tableHelp.text1">
					<template #issues>
						<n-button class="text-13px" type="primary" text @click="handleGoIssues">
							<span>Issues</span>
							<i class="i-mdi:arrow-right ml-1px"></i>
						</n-button>
					</template>
					<template #star>
						<n-button class="text-13px" type="primary" text @click="handleGoStar">
							Star
							<i class="i-mdi:arrow-right ml-1px"></i>
						</n-button>
					</template>
				</i18n-t>
				<br />
				<span>{{ $t('components.tableHelp.text2') }}</span>
			</div>
		</template>
	</n-empty>
</template>

<script lang="ts" setup>
const handleGoIssues = () => {
	window.open('https://github.com/aaPanel/BillionMail/issues')
}

const handleGoStar = () => {
	window.open('https://github.com/aaPanel/BillionMail')
}
</script>

<style lang="scss" scoped></style>
