<template>
 

<div class="min-h-screen flex flex-col bg-gray-50">
    <!-- Efek Es/Snow -->
    <SnowEffect />
    <!-- Navigation Bar -->
    <nav class="bg-indigo-700 text-white px-6 py-4 shadow">
      <div class="container mx-auto flex justify-between items-center">
        <div class="font-bold text-lg">Smart Library</div>
        <div class="space-x-4 flex items-center">
          <NuxtLink to="/" class="hover:underline">Home</NuxtLink>
          <NuxtLink to="/resources" class="hover:underline">Resources</NuxtLink>
          <NuxtLink to="/welcome" class="hover:underline">Welcome</NuxtLink>
          <button v-if="auth.user && auth.user.value" @click="handleLogout"
            class="ml-4 bg-white/90 text-indigo-700 px-3 py-1 rounded shadow hover:bg-indigo-50 font-semibold transition">
            Logout
          </button>
        </div>
      </div>
    </nav>

    <!-- Main Content -->
    <main class="flex-1 container mx-auto px-4 py-8">
      <slot />
    </main>

    <!-- Footer -->
    <footer class="bg-indigo-700 text-white text-center py-4 mt-8">
      &copy; {{ new Date().getFullYear() }} Smart Library. All rights reserved.
    </footer>
    <MusicPlayer />
  </div>
</template>

<script setup>
import SnowEffect from '@/components/SnowEffect.vue';
import MusicPlayer from '@/components/MusicPlayer.vue';
import { useRouter } from 'vue-router'
import { useAuth } from '~/stores/auth'
const auth = useAuth()
const router = useRouter()
function handleLogout() {
  auth.logout()
  router.push('/login')
}
</script>
