<template>
  <div class="login-wrapper">
    <div class="logo-title mb-6">
      <svg class="logo-book" width="48" height="48" viewBox="0 0 56 56" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="5" y="10" width="38" height="36" rx="7" fill="#f9e79f" stroke="#b7950b" stroke-width="2.5"/>
        <rect x="13" y="16" width="22" height="24" rx="4" fill="#fff" stroke="#b7950b" stroke-width="1.5"/>
        <path d="M15 20 Q24 28 33 20" stroke="#f7ca18" stroke-width="1.2" fill="none"/>
        <polygon points="32,16 39,16 35.5,28" fill="#f1948a"/>
      </svg>
      <h2 class="smart-library-title">Smart Library</h2>
    </div>
    <h1 class="text-3xl font-bold mb-4 text-center">Login</h1>
    <form @submit.prevent="onLogin" class="login-form">
      <div class="mb-4">
        <label for="email" class="block mb-1 font-semibold">Email</label>
        <input v-model="email" id="email" type="email" required autocomplete="email" class="w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-indigo-400" placeholder="Masukkan email" />
      </div>
      <div class="mb-6">
        <label for="password" class="block mb-1 font-semibold">Password</label>
        <div class="relative">
          <input
            v-model="password"
            :type="showPassword ? 'text' : 'password'"
            id="password"
            required
            autocomplete="current-password"
            class="w-full px-4 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-indigo-400 pr-12"
            placeholder="Masukkan password"
          />
          <button
            type="button"
            class="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-indigo-600 focus:outline-none"
            @click="showPassword = !showPassword"
            tabindex="-1"
          >
            <Icon v-if="showPassword" name="mdi:eye-off-outline" class="w-5 h-5" />
            <Icon v-else name="mdi:eye-outline" class="w-5 h-5" />
          </button>
        </div>
      </div>
      <button type="submit" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded font-semibold shadow">Login</button>
    </form>
    <div v-if="error" class="mt-4 text-red-600 font-semibold text-center">{{ error }}</div>
  </div>
</template>

<style scoped>
.login-wrapper {
  width: 100%;
  max-width: 600px;
  margin: 0 auto;
  background: rgba(255,255,255,0.96);
  border-radius: 1.5rem;
  box-shadow: 0 8px 32px 0 rgba(44,62,80,0.12), 0 1.5px 0 #e5e8ef inset;
  padding: 2.4rem 2.2rem 2.2rem 2.2rem;
  position: relative;
  z-index: 10;
  min-height: 480px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  transition: box-shadow 0.18s;
  overflow: hidden;
}
@media (max-width: 650px) {
  .login-wrapper {
    max-width: 98vw;
    border-radius: 1rem;
  }
}

.logo-title {
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: 1.2rem;
}
.logo-book {
  margin-bottom: 0.2rem;
  filter: drop-shadow(0 2px 8px rgba(183,149,11,0.10));
}
.smart-library-title {
  font-size: 1.5rem;
  font-weight: 800;
  color: #b7950b;
  letter-spacing: 0.02em;
  text-shadow: 0 2px 8px rgba(183,149,11,0.10);
  margin: 0;
  line-height: 1.1;
}
</style>


<script setup>

definePageMeta({ layout: 'auth' });

import { useRouter } from 'vue-router'
import { useAuth } from '~/stores/auth'

const email = ref('')
const password = ref('')
const showPassword = ref(false)
const router = useRouter()
const { login, error } = useAuth()

async function onLogin() {
  const success = await login(email.value, password.value)
  if (success) {
    // Ambil path asal dari localStorage, jika ada
    const redirectPath = localStorage.getItem('redirectAfterLogin') || '/'
    localStorage.removeItem('redirectAfterLogin')
    router.push(redirectPath)
  }
}

</script>
