<template>
  <div class="container mx-auto py-12 max-w-lg">
    <div class="mb-4">
      <NuxtLink to="/resources"
        class="inline-block bg-gray-200 hover:bg-gray-300 text-gray-800 font-semibold px-4 py-2 rounded shadow transition">
        &larr; Kembali</NuxtLink>
    </div>
    <h1 class="text-2xl font-bold mb-8 text-center">Tambah Resource</h1>
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
        {{ loading ? 'Menyimpan...' : 'Simpan Resource' }}
      </button>
      <div v-if="success" class="text-green-600 text-center font-semibold">Resource berhasil ditambahkan!</div>
      <div v-if="error" class="text-red-600 text-center font-semibold">Gagal menambah resource. {{ errorMsg }}</div>
    </form>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';
const router = useRouter();
definePageMeta({ middleware: 'auth' })

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
    // Submit dengan useFetch
    const { execute, data: res, error: submitError } = await useFetch('/api/resources', {
      baseURL: 'http://127.0.0.1:8000',
      method: 'POST',
      body,
      immediate: false,
    });
    await execute();
    if (!submitError.value) {
      success.value = true;
      setTimeout(() => router.push('/resources'), 1200);
    } else {
      error.value = true;
      errorMsg.value = submitError.value?.data?.message || 'Terjadi kesalahan.';
    }
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
