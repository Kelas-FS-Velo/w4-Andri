<template>
  <div class="container mx-auto py-12 max-w-lg">
    <div class="mb-4">
      <NuxtLink :to="backUrl"
        class="inline-block bg-gray-200 hover:bg-gray-300 text-gray-800 font-semibold px-4 py-2 rounded shadow transition">
        &larr; Kembali</NuxtLink>
    </div>
    <h1 class="text-2xl font-bold mb-8 text-center">Update Resource</h1>
    <form @submit.prevent="submitResource" class="bg-white shadow rounded-lg p-8 space-y-6">
      <div>
        <label class="block font-semibold mb-1">Resource Type</label>
        <select v-model="form.resource_type" class="w-full border rounded px-4 py-2 focus:ring-2 focus:ring-indigo-400"
          required>
          <option value="">Pilih tipe resource</option>
          <option value="book">Book</option>
          <option value="journal">Journal</option>
          <option value="magazine">Magazine</option>
          <option value="other">Other</option>
        </select>
      </div>
      <div>
        <label class="block font-semibold mb-1">Title</label>
        <input v-model="form.title" type="text"
          class="w-full border rounded px-4 py-2 focus:ring-2 focus:ring-indigo-400" required />
      </div>
      <div>
        <label class="block font-semibold mb-1">Author</label>
        <input v-model="form.author" type="text"
          class="w-full border rounded px-4 py-2 focus:ring-2 focus:ring-indigo-400" required />
      </div>
      <div>
        <label class="block font-semibold mb-1">Publication Date</label>
        <input v-model="form.publication_date" type="date"
          class="w-full border rounded px-4 py-2 focus:ring-2 focus:ring-indigo-400" required />
      </div>
      <div>
        <label class="block font-semibold mb-1">Genre</label>
        <input v-model="form.genre" type="text"
          class="w-full border rounded px-4 py-2 focus:ring-2 focus:ring-indigo-400" required />
      </div>
      <div>
        <label class="block font-semibold mb-1">ISBN</label>
        <input v-model="form.isbn" type="text"
          class="w-full border rounded px-4 py-2 focus:ring-2 focus:ring-indigo-400" required />
      </div>
      <div>
        <label class="block font-semibold mb-1">Summary</label>
        <textarea v-model="form.summary" rows="3"
          class="w-full border rounded px-4 py-2 focus:ring-2 focus:ring-indigo-400" required></textarea>
      </div>
      <div>
        <label class="block font-semibold mb-1">Cover Image URL</label>
        <input v-model="form.cover_image_url" type="url"
          class="w-full border rounded px-4 py-2 focus:ring-2 focus:ring-indigo-400" placeholder="https://..." />
      </div>
      <div>
        <label class="block font-semibold mb-1">Metadata (opsional, JSON)</label>
        <textarea v-model="form.metadata" rows="2"
          class="w-full border rounded px-4 py-2 focus:ring-2 focus:ring-indigo-400"
          placeholder='{"key":"value"}'></textarea>
        <div v-if="metadataError" class="text-xs text-red-500 mt-1">Format metadata harus JSON valid</div>
      </div>
      <button type="submit" :disabled="loading"
        class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 rounded shadow transition disabled:opacity-50">
        {{ loading ? 'Menyimpan...' : 'Simpan Perubahan' }}
      </button>
      <div v-if="success" class="text-green-600 text-center font-semibold">Resource berhasil diupdate!</div>
      <div v-if="error" class="text-red-600 text-center font-semibold">Gagal update resource. {{ errorMsg }}</div>
    </form>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue';
import { useRouter, useRoute } from 'vue-router';
definePageMeta({ middleware: 'auth' })
const router = useRouter();
const route = useRoute();

const backUrl = computed(() => {
  if (route.query.from === 'detail') {
    return `/resources/${route.params.id}`;
  }
  return '/resources';
});

const form = ref({
  title: '',
  author: '',
  publication_date: '',
  genre: '',
  resource_type: '',
  isbn: '',
  summary: '',
  cover_image_url: '',
  metadata: ''
});

// Fetch resource by id with useFetch
const { data: resourceData, pending: loadingResource, error: fetchError } = await useFetch(
  () => `/api/resources/${route.params.id}`,
  {
    baseURL: 'http://127.0.0.1:8000',
    immediate: true,
  }
);

watchEffect(() => {
  if (resourceData.value) {
    let pubDate = resourceData.value.publication_date;
    if (pubDate) {
      const d = new Date(pubDate);
      if (!isNaN(d.getTime())) {
        pubDate = d.toISOString().slice(0, 10);
      }
    }
    form.value = {
      title: resourceData.value.title,
      author: resourceData.value.author,
      publication_date: pubDate,
      genre: resourceData.value.genre,
      resource_type: resourceData.value.resource_type || '',
      isbn: resourceData.value.isbn || '',
      summary: resourceData.value.summary,
      cover_image_url: resourceData.value.cover_image_url,
      metadata: resourceData.value.metadata ? JSON.stringify(resourceData.value.metadata, null, 2) : ''
    };
  }
  if (fetchError.value) {
    error.value = true;
    errorMsg.value = 'Gagal mengambil data resource.';
  }
});
const loading = ref(false);
const success = ref(false);
const error = ref(false);
const errorMsg = ref('');
const metadataError = ref(false);

const submitResource = async () => {
  error.value = false;
  success.value = false;
  metadataError.value = false;

  let metadataObj = null;
  if (form.value.metadata) {
    try {
      metadataObj = JSON.parse(form.value.metadata);
    } catch (e) {
      metadataError.value = true;
      return;
    }
  }
  loading.value = true;
  try {
    const body = {
      ...form.value,
      metadata: metadataObj
    };
    const res = await $fetch(`/api/resources/${route.params.id}`, {
      baseURL: 'http://127.0.0.1:8000',
      method: 'PATCH',
      body
    });
    success.value = true;
    setTimeout(() => {
      if (route.query.from === 'detail') {
        router.push(`/resources/${route.params.id}`);
      } else {
        router.push('/resources');
      }
    }, 1200);
  } catch (e) {
    error.value = true;
    errorMsg.value = e?.data?.message || 'Terjadi kesalahan.';
  } finally {
    loading.value = false;
  }
}
</script>

<style scoped>
input,
textarea {
  background: #f9fafb;
}
</style>
