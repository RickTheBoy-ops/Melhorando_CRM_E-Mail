import { instance } from '@/api'
import i18n from '@/i18n'

const { t } = i18n.global

export const getVersionInfo = () => {
	return instance.get('/settings/get_version')
}

export const getServiceList = () => {
	return instance.get('/docker_api/list')
}

export const restartService = (params: { container_id: string }) => {
	return instance.post('/docker_api/restart', params, {
		fetchOptions: {
			loading: t('settings.api.loading.restarting'),
			successMessage: true,
		},
	})
}

export const getServiceConfig = (params: { service_type: string }) => {
	return instance.post('/services/get_config', params)
}

export const saveServiceConfig = (params: { service_type: string; content: string }) => {
	return instance.post('/services/save_config', params, {
		fetchOptions: {
			loading: t('settings.api.loading.saving'),
			successMessage: true,
		},
	})
}
