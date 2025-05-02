<template>
  <div class="container mx-auto py-8">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-2xl font-bold">Resource List</h1>
      <NuxtLink to="/resources/tambah"
        class="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold px-4 py-2 rounded shadow transition flex items-center gap-2">
        <Icon name="mdi:plus" class="w-5 h-5" /> Tambahkan
      </NuxtLink>
    </div>
    <table class="min-w-full bg-white border rounded-lg overflow-hidden">
      <thead class="bg-indigo-600 text-white">
        <tr>
          <th class="px-4 py-2">No.</th>
          <th class="px-4 py-2">Title</th>
          <th class="px-4 py-2">Author</th>
          <th class="px-4 py-2">Publication Date</th>
          <th class="px-4 py-2">Genre</th>
          <th class="px-4 py-2">Resource Type</th>
          <th class="px-4 py-2">ISBN</th>
          <th class="px-4 py-2">Summary</th>
          <th class="px-4 py-2">Cover Image</th>
          <th class="px-4 py-2">Metadata</th>
          <th class="px-4 py-2">Aksi</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-200">
        <tr v-if="pending">
          <td :colspan="13" class="py-12 text-gray-500" style="height: 300px; padding: 0;">
            <div class="flex flex-col justify-center items-center h-full w-full">
              <span class="inline-flex items-center gap-2 justify-center">
                <svg class="animate-spin h-5 w-5 text-indigo-500" xmlns="http://www.w3.org/2000/svg" fill="none"
                  viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                </svg>
                <span>Loading...</span>
              </span>
            </div>
          </td>
        </tr>
        <tr v-for="(resource, idx) in paginatedResources" :key="resource.id"
          class="hover:bg-indigo-50 transition-colors">
          <td class="px-4 py-2">{{ (currentPage - 1) * perPage + idx + 1 }}</td>
          <td class="px-4 py-2">{{ resource.title }}</td>
          <td class="px-4 py-2">{{ resource.author }}</td>
          <td class="px-4 py-2">{{ formatDate(resource.publication_date) }}</td>
          <td class="px-4 py-2">{{ resource.genre }}</td>
          <td class="px-4 py-2">{{ resource.resource_type || '-' }}</td>
          <td class="px-4 py-2">{{ resource.isbn || '-' }}</td>
          <td class="px-4 py-2">{{ resource.summary }}</td>
          <td class="px-4 py-2">
            <img :src="resource.cover_image_url || defaultCoverImage" alt="cover"
              class="w-16 h-16 object-cover rounded shadow" @error="onImgError" />
          </td>
          <td class="px-4 py-2">
            <pre
              class="text-xs whitespace-pre-wrap">{{ resource.metadata ? JSON.stringify(resource.metadata, null, 2) : '-' }}</pre>
          </td>
          <td class="px-4 py-2 text-center space-x-2">
            <NuxtLink :to="`/resources/${resource.id}`"
              class="inline-flex items-center border border-indigo-500 text-indigo-600 hover:bg-indigo-100 px-3 py-1 rounded shadow text-sm font-semibold transition">
              <Icon name="mdi:eye-outline" class="mr-1 w-4 h-4" />View
            </NuxtLink>
            <NuxtLink :to="`/resources/${resource.id}/update`"
              class="inline-flex items-center border border-yellow-400 text-yellow-600 hover:bg-yellow-100 px-3 py-1 rounded shadow text-sm font-semibold transition">
              <Icon name="mdi:pencil-outline" class="mr-1 w-4 h-4" />Edit
            </NuxtLink>
            <button @click="handleDelete(resource.id)"
              class="inline-flex items-center border border-red-500 text-red-600 hover:bg-red-100 px-3 py-1 rounded shadow text-sm font-semibold transition">
              <Icon name="mdi:trash-can-outline" class="mr-1 w-4 h-4" />Hapus
            </button>
          </td>
        </tr>
      </tbody>
    </table>
    <Pagination :total="resources.length" :perPage="perPage" :currentPage="currentPage"
      :perPageOptions="[5, 10, 20, 50]" @update:page="currentPage = $event" @update:perPage="handlePerPage" />
    <div v-if="pending" class="mt-4 text-gray-500">Loading...</div>
    <div v-if="error" class="mt-4 text-red-500">Failed to load resources.</div>
  </div>
</template>

<script setup>
definePageMeta({ middleware: 'auth' })
import Pagination from '@/components/Pagination.vue';
import { ref, computed } from 'vue';

function formatDate(dateStr) {
  if (!dateStr) return '-';
  const d = new Date(dateStr);
  if (isNaN(d)) return dateStr;
  return d.toLocaleDateString('id-ID', { day: '2-digit', month: 'long', year: 'numeric' });
}

const perPage = ref(10);
const currentPage = ref(1);

function handlePerPage(val) {
  perPage.value = val;
  currentPage.value = 1;
}


const { data, pending, error } = await useFetch('/api/resources', {
  baseURL: 'http://127.0.0.1:8000',
});
const resources = (data?.value?.data && data.value.data.length > 0) ? data.value.data : dummyResources;
const paginatedResources = computed(() => {
  const start = (currentPage.value - 1) * perPage.value;
  return resources.slice(start, start + perPage.value);
});
const dummyResources = [
  {
    id: 1,
    title: 'Belajar Laravel',
    author: 'Andri',
    publication_date: '2024-01-15',
    genre: 'Programming',
    resource_type: 'Book',
    isbn: '9786021234567',
    summary: 'Panduan lengkap belajar Laravel dari dasar hingga mahir.',
    cover_image_url: 'https://placehold.co/100x100/4f46e5/fff?text=Laravel',
    metadata: { level: 'Beginner', language: 'Indonesia' }
  },
  {
    id: 2,
    title: 'AI untuk Semua',
    author: 'Siti',
    publication_date: '2023-10-10',
    genre: 'Teknologi',
    resource_type: 'Book',
    isbn: '9786027654321',
    summary: 'Buku pengantar kecerdasan buatan untuk pemula.',
    cover_image_url: 'https://placehold.co/100x100/22d3ee/fff?text=AI',
    metadata: { pages: 200, language: 'Indonesia' }
  },
  {
    id: 3,
    title: 'Jurnal Sains 2025',
    author: 'Universitas X',
    publication_date: '2025-04-01',
    genre: 'Jurnal',
    resource_type: 'Journal',
    isbn: '9786029876543',
    summary: 'Kumpulan artikel sains terbaru.',
    cover_image_url: '',
    metadata: { volume: 3, issue: 1 }
  },
];
const router = useRouter ? useRouter() : null;

const handleDelete = async (id) => {
  if (!confirm('Yakin ingin menghapus resource ini?')) return;
  try {
    await $fetch(`/api/resources/${id}`, {
      baseURL: 'http://127.0.0.1:8000',
      method: 'DELETE',
    });
    // Refresh data
    window.location.reload();
  } catch (e) {
    alert('Gagal menghapus resource.');
  }
}
const defaultCoverImage = 'https://placehold.co/120x120/cccccc/fff?text=No+Image';

function onImgError(event) {
  event.target.src = defaultCoverImage;
}

</script>

<style scoped>
table {
  border-collapse: collapse;
}

th,
td {
  text-align: left;
}
</style>
