import { instance } from '@/api'
import i18n from '@/i18n'

const { t } = i18n.global

export const getForwardList = (params: {
	page: number
	page_size: number
	domain?: string
	keyword?: string
}) => {
	return instance.get('/mail_forward/list', { params })
}

type ForwardParams = {
	active: number
	address: string
	domain: string
	goto: string
}

export const addForward = (params: ForwardParams) => {
	return instance.post('/mail_forward/add', params, {
		fetchOptions: {
			loading: t('settings.forward.loading.adding'),
			successMessage: true,
		},
	})
}

export const editForward = (params: Omit<ForwardParams, 'domain'>) => {
	return instance.post('/mail_forward/edit', params, {
		fetchOptions: {
			loading: t('settings.forward.loading.editing'),
			successMessage: true,
		},
	})
}

export const deleteForward = (params: { address: string }) => {
	return instance.post('/mail_forward/delete', params, {
		fetchOptions: {
			loading: t('settings.forward.loading.deleting'),
			successMessage: true,
		},
	})
}
