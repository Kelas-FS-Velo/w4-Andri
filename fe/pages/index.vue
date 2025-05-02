<template>
  <div class="container mx-auto py-12">
    <div v-if="userInfo" class="mb-6 w-full flex justify-center">
      <div class="bg-white/80 rounded-xl px-6 py-4 shadow text-gray-800 text-center max-w-md">
        <div class="font-semibold mb-1">👋 Selamat datang, {{ userInfo.name || userInfo.email }}!</div>
        <div class="text-sm">Email: <span class="font-mono">{{ userInfo.email }}</span></div>
        <div class="text-sm">Role: <span class="font-semibold uppercase">{{ userInfo.role }}</span></div>
      </div>
    </div>
    <div class="flex flex-col md:flex-row md:items-center md:justify-between mb-8 gap-4">
      <div>
        <h1 class="text-3xl font-bold mb-2">Smart Library</h1>
        <p class="text-gray-600">Cari dan temukan berbagai sumber daya koleksi perpustakaan digital.</p>
      </div>
      <form @submit.prevent="searchResources" class="flex gap-2 mt-4 md:mt-0">
        <input v-model="keyword" type="text" placeholder="Cari judul atau penulis..."
          class="px-4 py-2 border rounded w-60 focus:outline-none focus:ring-2 focus:ring-indigo-400">
        <button type="submit"
          class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded font-semibold shadow">Cari</button>
      </form>
    </div>

    <div v-if="pending" class="text-gray-500 py-8">Loading...</div>
    <div v-else-if="filteredResources.length === 0" class="text-gray-500 py-8">Tidak ada resource ditemukan.</div>
    <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      <div v-for="resource in filteredResources" :key="resource.id"
        class="bg-white rounded-lg shadow p-5 flex flex-col">
        <div class="flex items-center gap-4 mb-2">
          <img :src="resource.cover_image_url || 'https://placehold.co/100x100/cccccc/fff?text=No+Image'" alt="cover"
            class="w-20 h-20 object-cover rounded shadow"
            @error="event => event.target.src = 'https://placehold.co/100x100/cccccc/fff?text=No+Image'" />
          <div>
            <h2 class="text-xl font-bold text-indigo-700">{{ resource.title }}</h2>
            <div class="text-gray-600 text-sm">{{ resource.author }}</div>
            <div class="text-gray-500 text-xs">{{ resource.publication_date }}</div>
          </div>
        </div>
        <div class="text-gray-700 mb-2 line-clamp-3">{{ resource.summary }}</div>
        <div class="flex flex-wrap gap-2 text-xs mb-2">
          <span class="bg-indigo-100 text-indigo-800 px-2 py-1 rounded">{{ resource.genre }}</span>
        </div>
        <div v-if="resource.metadata" class="bg-gray-50 p-2 rounded text-xs text-gray-600 mt-auto">
          <span class="font-semibold">Metadata:</span> {{ JSON.stringify(resource.metadata) }}
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { useAuth } from '~/stores/auth';
import axios from 'axios';

const keyword = ref('');
const { data, pending, error } = await useFetch('/api/resources', {
  baseURL: 'http://127.0.0.1:8000',
});
const resources = computed(() => data?.value?.data || []);

const filteredResources = computed(() => {
  if (!keyword.value) return resources.value;
  const lower = keyword.value.toLowerCase();
  return resources.value.filter(r =>
    r.title?.toLowerCase().includes(lower) ||
    r.author?.toLowerCase().includes(lower)
  );
});

// User info logic
const { user } = useAuth();
const userInfo = ref(null);
const userLoading = ref(false);

async function fetchUserInfo() {
  if (user.value && user.value.email) {
    userLoading.value = true;
    try {
      const res = await axios.get('http://127.0.0.1:8000/api/user', {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      userInfo.value = res.data;
    } catch {
      userInfo.value = user.value; // fallback
    } finally {
      userLoading.value = false;
    }
  } else {
    userInfo.value = null;
  }
}

onMounted(fetchUserInfo);

// Update info jika user berubah (misal: login/logout tanpa reload)
import { watch } from 'vue';
watch(user, fetchUserInfo, { immediate: false });

function searchResources() {
  // No-op, filtering is reactive
}
</script>

<style scoped>
.line-clamp-3 {
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
</style>