// router/index.js
import { createRouter, createWebHistory } from 'vue-router'
import roleMiddleware from '~/middleware/role'

const routes = [
  {
    path: '/',
    component: () => import('~/pages/welcome.vue')
  },
  {
    path: '/login',
    component: () => import('~/pages/login.vue')
  },
  {
    path: '/resources',
    component: () => import('~/pages/resources/index.vue'),
    beforeEnter: roleMiddleware(['admin', 'pustakawan'])
  },
  {
    path: '/resources/tambah',
    component: () => import('~/pages/resources/tambah.vue'),
    beforeEnter: roleMiddleware(['admin', 'pustakawan'])
  },
  // Contoh halaman admin-only
  {
    path: '/admin',
    component: () => import('~/pages/admin.vue'),
    beforeEnter: roleMiddleware(['admin'])
  },
  // Contoh halaman member-only
  {
    path: '/profile',
    component: () => import('~/pages/profile.vue'),
    beforeEnter: roleMiddleware(['member'])
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
