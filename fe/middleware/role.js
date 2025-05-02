// middleware/role.js
// Middleware frontend untuk validasi role user pada route tertentu
import { useAuth } from '~/stores/auth'

/**
 * Middleware untuk validasi role user
 * @param {Array<string>} allowedRoles - Daftar role yang diizinkan
 * @returns {function}
 */
export default function roleMiddleware(allowedRoles = []) {
  return (to, from, next) => {
    const { user } = useAuth()
    // Jika user belum login
    if (!user.value) {
      return next({ path: '/login', query: { redirect: to.fullPath } })
    }
    // Jika role user tidak sesuai
    if (!allowedRoles.includes(user.value.role)) {
      return next({ path: '/' })
    }
    // Role sesuai
    return next()
  }
}
