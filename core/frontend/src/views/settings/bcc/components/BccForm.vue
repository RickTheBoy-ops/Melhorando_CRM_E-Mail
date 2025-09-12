<template>
	<modal :title="title" width="500">
		<bt-form ref="formRef" class="pt-8px" :model="form" :rules="rules">
			<n-form-item :label="t('settings.bcc.needCopy')" path="user">
				<n-input
					v-model:value="form.address"
					:disabled="isEdit"
					:placeholder="t('settings.bcc.placeholders.needCopy')">
				</n-input>
			</n-form-item>
			<n-form-item :label="t('settings.bcc.copyTo')" path="forward_user">
				<n-input v-model:value="form.goto" :placeholder="t('settings.bcc.placeholders.copyTo')">
				</n-input>
			</n-form-item>
			<n-form-item :label="t('settings.bcc.type')" path="type">
				<n-select v-model:value="form.type" :options="typeOptions"></n-select>
			</n-form-item>
			<n-form-item :label="t('settings.bcc.status')" :show-feedback="false">
				<n-switch v-model:value="form.active" :checked-value="1" :unchecked-value="0"></n-switch>
			</n-form-item>
		</bt-form>
	</modal>
</template>

<script lang="ts" setup>
import { FormRules } from 'naive-ui'
import { useModal } from '@/hooks/modal/useModal'
import { addBcc, editBcc } from '@/api/modules/settings/bcc'
import type { Bcc } from '../type/base'

const { t } = useI18n()

const isEdit = ref(false)

const title = computed(() => (isEdit.value ? t('settings.bcc.edit') : t('settings.bcc.add')))

const formRef = useTemplateRef('formRef')

const id = ref(0)

const form = reactive({
	address: '',
	goto: '',
	type: 'sender',
	active: 1,
})

const typeOptions = computed(() => [
	{ label: t('settings.bcc.types.sender'), value: 'sender' },
	{ label: t('settings.bcc.types.recipient'), value: 'recipient' },
])

const rules: FormRules = {}

const [Modal, modalApi] = useModal({
	onChangeState: isOpen => {
		if (isOpen) {
			const state = modalApi.getState<{ isEdit: boolean; row: Bcc | null }>()
			const { row } = state
			isEdit.value = state.isEdit
			if (row) {
				id.value = row.id
				form.address = row.address
				form.goto = row.goto
				form.type = row.type
				form.active = row.active
			}
		} else {
			id.value = 0
			form.address = ''
			form.goto = ''
			form.type = 'sender'
			form.active = 1
		}
	},
	onConfirm: async () => {
		await formRef.value?.validate()
		if (isEdit.value) {
			await editBcc({ id: id.value, ...toRaw(form) })
		} else {
			await addBcc(toRaw(form))
		}
		const state = modalApi.getState<{ refresh: Function }>()
		state.refresh()
	},
})
</script>

<style lang="scss" scoped></style>
