<template>
  <div class="fixed bottom-6 right-6 z-[100] group" :class="{ 'w-[60px]': !expanded, 'w-auto': expanded }"
    @mouseenter="expanded = true" @mouseleave="expanded = false" @focusin="expanded = true" @focusout="expanded = false"
    style="transition:width 0.3s cubic-bezier(.4,0,.2,1);">
    <div class="bg-gray-900 shadow-2xl rounded-2xl flex items-center border border-gray-800 text-white h-[56px]"
      :class="expanded ? 'px-5 py-3 gap-3 min-w-0' : 'px-0 py-0 gap-0 min-w-0 justify-center'"
      style="transition:all 0.3s cubic-bezier(.4,0,.2,1);">
      <button @click="togglePlay"
        class="focus:outline-none flex-shrink-0 flex items-center justify-center rounded-full bg-gray-800 border border-gray-700 w-10 h-10 shadow-lg">
        <span v-if="!playing" title="Play" class="flex-shrink-0">
          <Icon name="material-symbols:play-arrow-outline-rounded" class="text-indigo-600" style="font-size:1.5rem;" />
        </span>
        <span v-else title="Pause" class="flex-shrink-0">
          <Icon name="material-symbols:pause-outline-rounded" class="text-indigo-600" style="font-size:1.5rem;" />
        </span>
      </button>
      <transition name="fade">
        <template v-if="expanded">
          <div class="flex items-center gap-2">
            <span class="ml-4 text-sm font-medium h-10 text-white max-w-[80px] overflow-hidden relative"
              style="display:inline-block;height:22px;">
              <template v-if="!loading">
                <span class="block whitespace-nowrap animate-marquee rounded px-2 py-0.5" style="min-width:100%;">
                  {{ playlist[current].title }}
                </span>
              </template>
              <template v-else>
                <svg class="inline animate-spin h-4 w-4 mr-1 text-indigo-300" xmlns="http://www.w3.org/2000/svg"
                  fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"></path>
                </svg>
                Loading...
              </template>
            </span>

            <button @click="nextRandom" title="Next random" class="ml-3 focus:outline-none">
              <Icon name="mdi:dice-multiple" class="h-6 w-6 text-indigo-300 hover:text-indigo-400" />
            </button>
            <button @click="autoplay = !autoplay" :title="autoplay ? 'Autoplay ON' : 'Autoplay OFF'"
              :class="['ml-2 focus:outline-none flex items-center gap-1', autoplay ? '' : 'opacity-70']">
              <svg xmlns="http://www.w3.org/2000/svg"
                :class="autoplay ? 'h-5 w-5 text-amber-400' : 'h-5 w-5 text-gray-400'" fill="none" viewBox="0 0 24 24"
                stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </button>
            <!-- Volume control -->
            <div class="flex items-center ml-4">
              <button @click="volume = volume === 0 ? prevVolume : 0" class="focus:outline-none">
                <svg v-if="volume === 0" xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-300" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 9v6h4l5 5V4l-5 5H9z" />
                  <line x1="19" y1="5" x2="5" y2="19" stroke="currentColor" stroke-width="2" />
                </svg>
                <svg v-else xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-indigo-400" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 9v6h4l5 5V4l-5 5H9z" />
                </svg>
              </button>
              <input type="range" min="0" max="1" step="0.01" v-model.number="volume" class="ml-2 w-10 align-middle" />
            </div>
          </div>
        </template>
      </transition>
    </div>
    <audio ref="audio" :src="playlist[current].src" @ended="onEnded" />
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue';
const playlist = [
  { title: 'Relaxing Jazz Saxophone Music. Saxophone Instruments music.  ', src: 'https://cdn.pixabay.com/download/audio/2025/02/19/audio_2802b6fb04.mp3?filename=relaxing-jazz-saxophone-music-saxophone-instruments-music-303093.mp3' },
  { title: 'Smooth Jazz Saxophone Solo with a LoFi Vibe', src: 'https://cdn.pixabay.com/download/audio/2024/10/22/audio_5b87be5f9b.mp3?filename=smooth-jazz-saxophone-solo-with-a-lofi-vibe-253950.mp3' },
  { title: 'Sax (solo) jazz', src: 'https://cdn.pixabay.com/download/audio/2025/04/01/audio_8aad6c9b22.mp3?filename=sax-solo-jazz-321543.mp3' },
  { title: 'Smooth Jazz Cafe Session 1', src: 'https://cdn.pixabay.com/download/audio/2025/02/26/audio_af3ca465ca.mp3?filename=smooth-jazz-cafe-session-1-306314.mp3' },
  { title: 'Smooth Jazz Cafe Session 3', src: 'https://cdn.pixabay.com/download/audio/2025/02/26/audio_d1c79b5797.mp3?filename=smooth-jazz-cafe-session-3-306316.mp3' },
  
];
const audio = ref(null);
const playing = ref(false);

function handleKeydown(e) {
  // Jika sedang fokus di input/textarea, abaikan
  const tag = document.activeElement?.tagName?.toLowerCase();
  if (tag === 'input' || tag === 'textarea') return;
  if (e.code === 'Space') {
    e.preventDefault();
    togglePlay();
  } else if (e.code === 'ArrowRight') {
    e.preventDefault();
    nextRandom();
  }
}

onMounted(() => {
  window.addEventListener('keydown', handleKeydown);
  // Set volume awal ke 50%
  volume.value = 0.5;
  prevVolume.value = 0.5;
  if (audio.value) audio.value.volume = 0.5;
});
onBeforeUnmount(() => {
  window.removeEventListener('keydown', handleKeydown);
});
const current = ref(Math.floor(Math.random() * playlist.length));
const loading = ref(false);
const expanded = ref(false);
const autoplay = ref(true);
const volume = ref(0.5);
const prevVolume = ref(0.5);

function togglePlay() {
  if (!audio.value) return;
  if (playing.value) {
    audio.value.pause();
    playing.value = false;
  } else {
    if (audio.value.readyState < 4) {
      loading.value = true;
      // Akan play otomatis saat canplaythrough
    } else {
      audio.value.play();
    }
    playing.value = true;
  }
}

function onEnded() {
  playing.value = false;
  if (autoplay.value) {
    nextRandom();
    setTimeout(() => {
      if (audio.value) {
        audio.value.play();
        playing.value = true;
      }
    }, 200);
  }
}

// Watch volume changes and set to audio element
watch(volume, (val, oldVal) => {
  if (audio.value) {
    audio.value.volume = val;
  }
  if (val > 0) prevVolume.value = val;
});

// Set initial volume on mount
onMounted(() => {
  if (audio.value) {
    audio.value.volume = volume.value;
  }
});



import { watch } from 'vue';

const preloadedAudio = ref(null);

function nextRandom() {
  if (playlist.length <= 1) return;
  let next;
  do {
    next = Math.floor(Math.random() * playlist.length);
  } while (next === current.value);

  // Preload the next song's audio
  if (preloadedAudio.value) {
    preloadedAudio.value.src = '';
    preloadedAudio.value = null;
  }
  preloadedAudio.value = new Audio();
  preloadedAudio.value.src = playlist[next].src;
  preloadedAudio.value.load();

  current.value = next;
  // Jika autoplay aktif, langsung play lagu berikutnya
  if (autoplay.value) {
    playing.value = true;
    if (audio.value) {
      if (audio.value.readyState < 4) {
        loading.value = true;
      } else {
        audio.value.play();
      }
    }
  } else {
    playing.value = false;
    if (audio.value) audio.value.pause();
  }
}

// Preload next song after current changes
watch(current, (val) => {
  if (playlist.length <= 1) return;
  let next;
  do {
    next = Math.floor(Math.random() * playlist.length);
  } while (next === val);
  if (preloadedAudio.value) {
    preloadedAudio.value.src = '';
    preloadedAudio.value = null;
  }
  preloadedAudio.value = new Audio();
  preloadedAudio.value.src = playlist[next].src;
  preloadedAudio.value.load();
});

watch(current, () => {
  if (audio.value) {
    audio.value.currentTime = 0;
    if (autoplay.value) {
      playing.value = true;
      if (audio.value.readyState < 4) {
        loading.value = true;
        // Akan play otomatis saat canplaythrough
      } else {
        audio.value.play();
      }
    } else {
      if (playing.value) {
        if (audio.value.readyState < 4) {
          loading.value = true;
        } else {
          audio.value.play();
        }
      } else {
        audio.value.pause();
      }
    }
  }
});

// Pastikan event listener tidak dobel
watch(audio, (newAudio, oldAudio) => {
  if (oldAudio) oldAudio.removeEventListener('canplaythrough', onCanPlayThrough);
  if (newAudio) newAudio.addEventListener('canplaythrough', onCanPlayThrough);
});

function onCanPlayThrough() {
  if (loading.value && playing.value) {
    audio.value.play();
  }
  loading.value = false;
}

</script>

<style scoped>
/* Volume slider abu-abu */
input[type="range"].volume-slider-vertical {
  accent-color: #9ca3af;
  /* Tailwind gray-400 */
}

/* Untuk browser yang tidak support accent-color, custom thumb dan track */
input[type="range"].volume-slider-vertical::-webkit-slider-thumb {
  background: #9ca3af;
}

input[type="range"].volume-slider-vertical::-webkit-slider-runnable-track {
  background: #e5e7eb;
}

input[type="range"].volume-slider-vertical::-moz-range-thumb {
  background: #9ca3af;
}

input[type="range"].volume-slider-vertical::-moz-range-track {
  background: #e5e7eb;
}

input[type="range"].volume-slider-vertical::-ms-thumb {
  background: #9ca3af;
}

input[type="range"].volume-slider-vertical::-ms-fill-lower {
  background: #e5e7eb;
}

input[type="range"].volume-slider-vertical::-ms-fill-upper {
  background: #e5e7eb;
}

/* Responsive for mobile */
@media (max-width: 640px) {
  .fixed.bottom-6.right-6 {
    bottom: 1rem;
    right: 1rem;
    padding: 0.5rem 1rem;
  }
}

@keyframes marquee {
  0% {
    transform: translateX(100%);
  }

  100% {
    transform: translateX(-100%);
  }
}

.animate-marquee {
  animation: marquee 7s linear infinite;
}
</style>
