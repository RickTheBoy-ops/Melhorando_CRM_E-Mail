import { RouteRecordRaw } from 'vue-router'
import { Layout } from '@/router/constant'

const route: RouteRecordRaw = {
	path: '/smtp',
	component: Layout,
	meta: { sort: 8, hidden: false, key: 'smtp', title: 'SMTP', titleKey: '' },
	children: [
		{
			path: '/smtp',
			name: 'SMTP',
			component: () => import('@/views/smtp/index.vue'),
		},
	],
}

export default route
