import { instance } from '@/api'
import i18n from '@/i18n'

const { t } = i18n.global

export const getBccList = (params: {
	page: number
	page_size: number
	domain?: string
	keyword?: string
}) => {
	return instance.get('/mail_bcc/list', { params })
}

type BccParams = {
	type: string
	address: string
	goto: string
	active: number
}

export const addBcc = (params: BccParams) => {
	return instance.post('/mail_bcc/add', params, {
		fetchOptions: {
			loading: t('settings.bcc.loading.adding'),
			successMessage: true,
		},
	})
}

export const editBcc = (params: BccParams & { id: number }) => {
	return instance.post('/mail_bcc/edit', params, {
		fetchOptions: {
			loading: t('settings.bcc.loading.saving'),
			successMessage: true,
		},
	})
}

export const deleteBcc = (params: { id: number }) => {
	return instance.post('/mail_bcc/delete', params, {
		fetchOptions: {
			loading: t('settings.bcc.loading.deleting'),
			successMessage: true,
		},
	})
}
