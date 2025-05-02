<template>
  <div class="bg-white/80 dark:bg-gray-900/80 border border-gray-200 dark:border-gray-700 rounded-xl px-6 py-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4 mt-6 transition-all">
    <div class="flex flex-col sm:flex-row sm:items-center sm:gap-2">
      <label class="mr-2 font-semibold text-gray-700 dark:text-gray-200">Tampilkan</label>
      <select v-model.number="localPerPage" @change="emitPerPage" class="border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-1.5 focus:ring-2 focus:ring-indigo-400 focus:outline-none bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-200 transition">
        <option v-for="opt in perPageOptions" :key="opt" :value="opt">{{ opt }}</option>
      </select>
      <span class="ml-2 text-gray-500 dark:text-gray-400">per halaman</span>
      <span class="ml-4 text-xs italic text-gray-400 dark:text-gray-500">Dari {{ total }} data</span>
    </div>
    <div class="flex items-center gap-3">
      <div class="flex items-center gap-2">
        <label for="page-select" class="sr-only">Pilih halaman</label>
        <select id="page-select" v-model.number="dropdownPage" @change="goToPage(dropdownPage)" class="border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-1.5 focus:ring-2 focus:ring-indigo-400 focus:outline-none bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-200 transition">
          <option v-for="p in totalPages" :key="p" :value="p">Halaman {{ p }}</option>
        </select>
      </div>
      <button @click="goToPage(currentPage - 1)" :disabled="currentPage === 1"
        class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400 hover:bg-indigo-50 dark:hover:bg-gray-700 focus:ring-2 focus:ring-indigo-400 focus:outline-none transition disabled:opacity-60 disabled:cursor-not-allowed">
        <svg xmlns='http://www.w3.org/2000/svg' class='h-4 w-4' fill='none' viewBox='0 0 24 24' stroke='currentColor'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M15 19l-7-7 7-7'/></svg>
      </button>
      <button @click="goToPage(currentPage + 1)" :disabled="currentPage === totalPages"
        class="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400 hover:bg-indigo-50 dark:hover:bg-gray-700 focus:ring-2 focus:ring-indigo-400 focus:outline-none transition disabled:opacity-60 disabled:cursor-not-allowed">
        <svg xmlns='http://www.w3.org/2000/svg' class='h-4 w-4' fill='none' viewBox='0 0 24 24' stroke='currentColor'><path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M9 5l7 7-7 7'/></svg>
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue';

const props = defineProps({
  total: { type: Number, required: true },
  perPage: { type: Number, required: true },
  currentPage: { type: Number, default: 1 },
  perPageOptions: { type: Array, default: () => [5, 10, 20, 50] }
});

// Dropdown page binding
const dropdownPage = ref(props.currentPage);
watch(() => props.currentPage, (val) => { dropdownPage.value = val; });

const emit = defineEmits(['update:page', 'update:perPage']);
const localPerPage = ref(props.perPage);

const totalPages = computed(() => Math.max(1, Math.ceil(props.total / localPerPage.value)));

const visiblePages = computed(() => {
  const pages = [];
  let start = Math.max(1, props.currentPage - 2);
  let end = Math.min(totalPages.value, props.currentPage + 2);
  if (end - start < 4) {
    if (start === 1) {
      end = Math.min(totalPages.value, start + 4);
    } else if (end === totalPages.value) {
      start = Math.max(1, end - 4);
    }
  }
  for (let i = start; i <= end; i++) pages.push(i);
  return pages;
});

function goToPage(page) {
  if (page >= 1 && page <= totalPages.value) {
    emit('update:page', page);
  }
}
function emitPerPage() {
  emit('update:perPage', localPerPage.value);
}

watch(() => props.perPage, (val) => {
  localPerPage.value = val;
});
</script>
