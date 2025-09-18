import { useGlobalStore, useUserStore } from '@/store'
import { setLanguage } from '@/i18n'
import { clearPendingRequests } from '@/api'
import { routes } from '@/router/router'
import router from '@/router/router'
import loadingBar from '@/config/loadingBar'

// Route white list
const whitePathList = ['/login']

router.beforeEach(async (to, from, next) => {
	loadingBar.start()

	clearPendingRequests()

	const globalStore = useGlobalStore()

	// Set the language
		try {
			await globalStore.getLang()
			// Garantir que o idioma seja sempre português do Brasil
			if (globalStore.lang !== 'pt-br') {
				globalStore.lang = 'pt-br'
			}
			setLanguage()
		} catch {
			// Em caso de erro, definir o idioma como português do Brasil
			globalStore.lang = 'pt-br'
			setLanguage()
		}

	// Check if the visited route exists in the registered routes
	const routeExists = routes.some(route => route.path === to.path)

	// If the route does not exist, go directly
	if (!routeExists) {
		next()
		return
	}

	const userStore = useUserStore()

	// User is logged in
	if (userStore.isLogin) {
		// If the visited route is in the white list, jump to the home page
		if (whitePathList.includes(to.path)) {
			next('/')
		} else {
			next()
		}
	} else if (whitePathList.includes(to.path)) {
		// If the visited route is in the white list, go directly
		next()
	} else {
		next('/login')
	}
})

router.afterEach(() => {
	loadingBar.finish()
})

export default router
