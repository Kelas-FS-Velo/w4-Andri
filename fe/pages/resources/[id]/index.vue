<template>
  <div class="container mx-auto py-12 max-w-lg">
    <div class="mb-4">
      <NuxtLink to="/resources"
        class="inline-block bg-gray-200 hover:bg-gray-300 text-gray-800 font-semibold px-4 py-2 rounded shadow transition">
        &larr; Kembali</NuxtLink>
    </div>
    <div v-if="pending" class="text-gray-500 py-8">Loading...</div>
    <div v-else-if="error" class="text-red-500 py-8">Gagal memuat data resource.</div>
    <div v-else class="bg-white shadow rounded-lg p-8">
      <h1 class="text-2xl font-bold mb-4 text-center">{{ resource.title }}</h1>
      <div class="grid grid-cols-2 gap-4 items-start mb-6">
        <div class="col-span-2 flex justify-center gap-3 mb-2">
          <NuxtLink :to="`/resources/${route.params.id}/update?from=detail`" class="bg-yellow-400 hover:bg-yellow-500 text-white px-4 py-2 rounded shadow font-semibold">Edit</NuxtLink>
          <button @click="handleDelete" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded shadow font-semibold">Hapus</button>
        </div>
        <div class="col-span-2 flex flex-col items-center mb-2">
          <img :src="resource.cover_image_url || defaultImg" @error="e => { e.target.src = defaultImg }" alt="cover"
            class="w-32 h-32 object-cover rounded shadow" />
        </div>
        <div class="font-semibold">Author:</div>
        <div>{{ resource.author }}</div>
        <div class="font-semibold">Publication Date:</div>
        <div>{{ resource.publication_date }}</div>
        <div class="font-semibold">Genre:</div>
        <div>{{ resource.genre }}</div>
        <div class="font-semibold">Resource Type:</div>
        <div>{{ resource.resource_type || '-' }}</div>
        <div class="font-semibold">ISBN:</div>
        <div>{{ resource.isbn || '-' }}</div>
        <div class="font-semibold">Summary:</div>
        <div>{{ resource.summary }}</div>
      </div>
      <div>
        <span class="font-semibold">Metadata:</span>
        <pre
          class="text-xs whitespace-pre-wrap bg-gray-50 rounded p-2 mt-1">{{ resource.metadata ? JSON.stringify(resource.metadata, null, 2) : '-' }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { useRoute, useRouter } from 'vue-router';
import { ref, computed } from 'vue';
definePageMeta({ middleware: 'auth' })

const defaultImg = 'https://placehold.co/120x120/cccccc/fff?text=No+Image';
const route = useRoute();
const router = useRouter();
const { data, pending, error } = await useFetch(() => `/api/resources/${route.params.id}`, {
  baseURL: 'http://127.0.0.1:8000',
});
const resource = computed(() => data?.value || {});

const handleDelete = async () => {
  if (!confirm('Yakin ingin menghapus resource ini?')) return;
  try {
    await $fetch(`/api/resources/${route.params.id}`, {
      baseURL: 'http://127.0.0.1:8000',
      method: 'DELETE',
    });
    router.push('/resources');
  } catch (e) {
    alert('Gagal menghapus resource.');
  }
};
</script>

<style scoped>
input,
textarea {
  background: #f9fafb;
}
</style>
