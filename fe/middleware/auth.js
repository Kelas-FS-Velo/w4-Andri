import { useAuth } from '~/stores/auth'

export default defineNuxtRouteMiddleware(async (to, from) => {
  const auth = useAuth()
  // Load user info dari token jika belum ada
  if (!auth.user.value || !auth.token.value) {
    await auth.loadUser()
  }
  // Jika setelah load user tetap belum login, redirect ke login
  if (!auth.user.value) {
    return navigateTo('/login')
  }
})
