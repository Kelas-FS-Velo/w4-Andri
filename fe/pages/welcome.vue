<template>
    <div>
        <!-- <NuxtRouteAnnouncer />
      <NuxtWelcome /> -->
        <div
            class="min-h-screen flex flex-col bg-gradient-to-br from-blue-900 via-indigo-800 to-cyan-700 text-center font-pt-sans py-0 space-y-0 relative">
            <nav class="w-full px-6 py-4 fixed top-0 transition-all duration-300"
                :class="{ 'bg-indigo-800 shadow-md': scrolled, 'bg-transparent': !scrolled }">
                <div class="max-w-7xl mx-auto flex justify-between items-center">
                    <!-- Logo -->
                    <div>
                        <img src="/images/logo.svg" alt="Logo" class="h-15" />
                    </div>

                    <!-- Social Media Icons -->
                    <div class="flex space-x-4">
                        <a href="#"
                            class="w-10 h-10 border-2 border-gray-200 rounded-full flex items-center justify-center hover:border-white">
                            <Icon name="mdi:linkedin" class="w-6 h-6 text-gray-200 hover:text-white" />
                        </a>
                        <a href="#"
                            class="w-10 h-10 border-2 border-gray-200 rounded-full flex items-center justify-center hover:border-white">
                            <Icon name="mdi:twitter" class="w-6 h-6 text-gray-200 hover:text-white" />
                        </a>
                        <a href="#"
                            class="w-10 h-10 border-2 border-gray-200 rounded-full flex items-center justify-center hover:border-white">
                            <Icon name="mdi:github" class="w-6 h-6 text-gray-200 hover:text-white" />
                        </a>
                    </div>
                </div>
            </nav>
            <div
                class="container mx-auto max-w-2xl px-6 pt-44 space-y-6 flex-grow flex flex-col items-center justify-center">
                <h1 class="text-3xl md:text-4xl font-bold text-white">
                    {{ profile?.title }}
                </h1>
                <div class="text-2xl uppercase text-white font-semibold">
                    {{ profile?.name }}
                </div>
                <p class="text-white text-center">
                    {{ profile?.description }}
                </p>

                <div class="flex justify-center my-8">
                    <div class="w-24 h-24 md:w-44 md:h-44 bg-indigo-500 rounded-full flex items-center justify-center">
                        <img src="/images/avatar-andri.png" alt="Avatar" class="rounded-full" />
                    </div>
                </div>

                <div class="">
                    <img src="/images/desk.png" alt="Desk" class="w-[500px] h-auto object-cover opacity-90" />
                </div>
            </div>

        </div>
    </div>
</template>
<script setup>

definePageMeta({ layout: 'empty' })

const scrolled = ref(false);
const { data: profile } = await useFetch('/api/profile', { baseURL: 'http://127.0.0.1:8000' })


const handleScroll = () => {
    scrolled.value = window.scrollY > 50;
};

onMounted(() => {
    window.addEventListener('scroll', handleScroll);

});

onUnmounted(() => {
    window.removeEventListener('scroll', handleScroll);
});
</script>

<style>
@import url('https://fonts.googleapis.com/css2?family=PT+Sans:wght@400;700&display=swap');

.font-pt-sans {
    font-family: 'PT Sans', sans-serif;
}
</style>