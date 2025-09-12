import { createPinia } from 'pinia'
import piniaPluginPersistedstate from 'pinia-plugin-persistedstate'
import useMenuStore from './modules/menu'
import useUserStore from './modules/user'
import useGlobalStore from './modules/global'
import useThemeStore from './modules/theme'

const pinia = createPinia()
pinia.use(piniaPluginPersistedstate)

export { useMenuStore, useUserStore, useGlobalStore, useThemeStore }

export default pinia
