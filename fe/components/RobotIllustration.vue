<template>
  <div class="illustration indigo-bg-gradient">
    <button @click="toggleSpeech"
      class="absolute top-2 right-3 z-10 bg-white/80 text-indigo-600 px-3 py-1 rounded shadow text-xs font-semibold hover:bg-indigo-50 transition">
      <span v-if="speechEnabled">🔊 Suara ON</span>
      <span v-else>🔇 Suara OFF</span>
    </button>
    <transition name="bubble-fade" mode="out-in">
      <div class="robot-quote-bubble" :key="currentQuote">
        <span v-if="isLoading">
          <svg class="inline animate-spin h-5 w-5 text-indigo-400 mr-2 align-middle" xmlns="http://www.w3.org/2000/svg"
            fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"></path>
          </svg>
          Memproses suara...
        </span>
        <span v-else-if="isSpeaking || !speechEnabled">{{ currentQuote }}</span>
      </div>
    </transition>
    <svg width="440" height="360" viewBox="0 0 440 360" fill="none" xmlns="http://www.w3.org/2000/svg">
      <g :transform="`translate(0,${bodyFloatY})`">
        <defs>
          <radialGradient id="robotGlow" cx="0.5" cy="0.5" r="0.7">
            <stop offset="0%" stop-color="#eaf6fb" stop-opacity="0.8" />
            <stop offset="100%" stop-color="#aed6f1" stop-opacity="0.15" />
          </radialGradient>
          <linearGradient id="robotBody" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#aed6f1" />
            <stop offset="100%" stop-color="#5dade2" />
          </linearGradient>
          <filter id="eyeGlow" x="-20" y="-20" width="60" height="60">
            <feFlood flood-color="#90caf9" result="flood" />
            <feComposite in="flood" in2="SourceGraphic" operator="in" result="mask" />
            <feGaussianBlur in="mask" stdDeviation="3.5" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <linearGradient id="robotAccent" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#f9e79f" />
            <stop offset="100%" stop-color="#f7ca18" />
          </linearGradient>
        </defs>
        <!-- Background Glow -->
        <ellipse cx="220" cy="190" rx="170" ry="110" fill="url(#robotGlow)" />
        <!-- Pantulan cahaya badan -->
        <ellipse cx="170" cy="145" rx="38" ry="16" fill="#fff" fill-opacity="0.18" />
        <!-- Robot body -->
        <rect x="140" y="120" width="160" height="120" rx="40" fill="url(#robotBody)" stroke="#2874a6"
          stroke-width="5" />
        <!-- Pantulan cahaya kepala -->
        <ellipse cx="190" cy="90" rx="22" ry="10" fill="#fff" fill-opacity="0.23" />
        <!-- Robot head -->
        <rect x="170" y="75" width="100" height="90" rx="32" fill="#fff" stroke="#2874a6" stroke-width="4" />
        <!-- Eyes -->
        <ellipse cx="200" cy="115" rx="10" :ry="eyeRy" fill="#90caf9" stroke="#154360" stroke-width="2"
          :filter="'url(#eyeGlow)'" :style="'transition: ry 0.15s cubic-bezier(.4,2,.6,1);'" />
        <ellipse cx="240" cy="115" rx="10" :ry="eyeRy" fill="#90caf9" stroke="#154360" stroke-width="2"
          :filter="'url(#eyeGlow)'" :style="'transition: ry 0.15s cubic-bezier(.4,2,.6,1);'" />
        <!-- Refleksi cahaya mata kiri -->
        <ellipse cx="196" :cy="eyeRy > 2 ? 111 : 115" rx="4.5" :ry="eyeRy > 2 ? 2.7 : 1.5" fill="#fff"
          fill-opacity="0.75" />
        <!-- Refleksi cahaya mata kanan -->
        <ellipse cx="236" :cy="eyeRy > 2 ? 111 : 115" rx="4.5" :ry="eyeRy > 2 ? 2.7 : 1.5" fill="#fff"
          fill-opacity="0.75" />
        <ellipse cx="220" :cy="isSpeaking ? mouthCy : 145" :rx="isSpeaking ? mouthRx : 15"
          :ry="isSpeaking ? mouthRy : 6" fill="#154360" />
        <!-- Antenna -->
        <rect x="215" y="55" width="10" height="20" rx="4" fill="#5dade2" />
        <circle cx="220" cy="50" r="7" fill="#f7ca18" stroke="#b7950b" stroke-width="2" />
        <!-- Arms -->
        <rect x="105" y="160" width="30" height="15" rx="7" fill="#aed6f1" stroke="#2874a6" stroke-width="3" />
        <rect x="305" y="160" width="30" height="15" rx="7" fill="#aed6f1" stroke="#2874a6" stroke-width="3" />
        <!-- Hands holding book -->
        <ellipse cx="120" cy="175" rx="10" ry="8" fill="#f7ca18" stroke="#b7950b" stroke-width="2" />
        <ellipse cx="320" cy="175" rx="10" ry="8" fill="#f7ca18" stroke="#b7950b" stroke-width="2" />
        <!-- Book -->
      </g>
      <g>
        <!-- Book (more detailed) -->
        <rect x="175" y="195" width="90" height="60" rx="10" fill="#fff" stroke="#b7950b" stroke-width="3" />
        <!-- Left page shading -->
        <rect x="175" y="195" width="45" height="60" rx="10" fill="#f9e79f" stroke="#b7950b" stroke-width="2" />
        <!-- Center fold shadow -->
        <rect x="218" y="197" width="4" height="56" rx="2" fill="#e5c07b" fill-opacity="0.25" stroke="none" />
        <!-- Center line -->
        <line x1="220" y1="197" x2="220" y2="253" stroke="#b7950b" stroke-width="2" />
        <!-- Page outlines -->
        <path d="M175 195 Q185 225 175 255" stroke="#b7950b" stroke-width="1" fill="none" />
        <path d="M265 195 Q255 225 265 255" stroke="#b7950b" stroke-width="1" fill="none" />
        <!-- Book content lines -->
        <rect x="190" y="210" width="60" height="8" rx="2" fill="#f7ca18" />
        <rect x="190" y="225" width="60" height="8" rx="2" fill="#f7ca18" />
      </g>
      <!-- Decorative dots -->
      <circle cx="400" cy="60" r="6" fill="#5dade2" />
      <circle cx="50" cy="70" r="4" fill="#f7ca18" />
      <circle cx="220" cy="320" r="5" fill="#229954" />
      <!-- Extra: cloud -->
      <ellipse cx="370" cy="80" rx="22" ry="10" fill="#d6eaf8" />
      <ellipse cx="385" cy="85" rx="10" ry="5" fill="#d6eaf8" />
    </svg>
    <p class="illustration-caption">Robot pintar siap membantu<br>belajar dan membaca buku</p>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, watch } from 'vue';

const quotes = [
  'Belajar adalah investasi terbaik untuk masa depan.',
  'Buku adalah jendela dunia, ayo baca setiap hari!',
  'Teknologi memudahkan kita menggapai ilmu.',
  'Jangan takut mencoba hal baru, teruslah belajar!',
  'Saya selalu siap menemani belajar kamu!',
  'Setiap hari adalah kesempatan untuk menjadi lebih baik.',
  'Kesuksesan berawal dari kemauan untuk mencoba.',
  'Membaca satu buku sama dengan membuka seribu jendela.',
  'Jangan pernah menyerah, kegagalan adalah bagian dari proses belajar.',
  'Ilmu yang bermanfaat akan selalu hidup meski waktu berlalu.',
  'Semangat pagi! Mari mulai hari dengan pengetahuan baru.',
  'Teknologi diciptakan untuk membantu manusia berkembang.',
  'Setiap pertanyaan adalah awal dari pengetahuan.',
  'Belajar bukan hanya di sekolah, tapi sepanjang hayat.',
  'Kegigihan adalah kunci utama dalam meraih cita-cita.',
  'Bersama saya yang pintar, belajar jadi lebih menyenangkan!',
  'Jangan takut salah, dari kesalahan kita belajar.',
  'Waktu yang digunakan untuk belajar tidak pernah sia-sia.',
  'Cita-cita setinggi langit, semangat belajar harus lebih tinggi!',
  'Setiap detik yang digunakan untuk membaca adalah investasi masa depan.',
  'Jadilah pembelajar seumur hidup.',
  'Buku adalah sahabat terbaik sepanjang masa.',
  'Teknologi dan literasi, kombinasi masa depan cerah.',
  'Belajar hari ini untuk masa depan yang lebih baik.',
  'Saya yang pintar selalu siap membantu kapan saja.',
  'Jangan ragu bertanya, karena bertanya tanda ingin tahu.',
  'Ilmu pengetahuan adalah cahaya kehidupan.',
  'Membaca memperluas wawasan dan membuka pikiran.',
  'Setiap tantangan adalah peluang untuk belajar.',
  'Semakin banyak membaca, semakin banyak tahu.',
  'Belajar bersama saya, belajar tanpa batas.',
  'Pengetahuan adalah kekuatan.',
  'Teknologi memudahkan akses ke ilmu pengetahuan.',
  'Buku adalah teman setia di setiap perjalanan.',
  'Jangan pernah berhenti belajar, dunia terus berubah.',
  'Saya suka belajar, bagaimana dengan kamu?',
  'Semangat belajar adalah modal utama menuju sukses.',
  'Setiap hari adalah hari baru untuk belajar hal baru.',
  'Belajar membuat hidup lebih bermakna.',
  'Teknologi dan buku, dua sahabat sejati.',
  'Saya yang pintar, teman belajar sepanjang waktu.',
  'Membaca adalah kunci membuka dunia.',
  'Ilmu pengetahuan tidak pernah habis untuk dipelajari.',
  'Semakin banyak bertanya, semakin banyak tahu.',
  'Belajar dari pengalaman adalah guru terbaik.',
  'Saya siap menemani belajar kapan saja.',
  'Buku dan teknologi, kombinasi sempurna.',
  'Setiap usaha belajar pasti membuahkan hasil.',
  'Jangan takut gagal, teruslah mencoba.',
  'Teknologi mempercepat proses belajar.',
  'Saya senang jika kamu rajin membaca.',
  'Belajar adalah perjalanan tanpa akhir.',
  'Ilmu yang didapat hari ini, bekal untuk esok.',
  'Saya yang pintar selalu mendukung semangat belajarmu.',
  'Buku adalah sumber inspirasi dan motivasi.',
  'Jangan lelah belajar, hasilnya akan terasa nanti.',
  'Teknologi membuat belajar jadi lebih mudah.',
  'Saya ingin kamu jadi pembelajar sejati.',
  'Setiap hari belajar, setiap hari berkembang.',
  'Buku adalah harta karun pengetahuan.',
  'Belajar bersama saya, belajar jadi seru.',
  'Teknologi membantu kita menemukan jawaban.',
  'Saya selalu siap menjawab pertanyaanmu.',
  'Belajar adalah kunci sukses di masa depan.',
  'Buku adalah jembatan menuju ilmu pengetahuan.',
  'Teknologi dan belajar, pasangan yang hebat.',
  'Saya suka membaca, yuk baca bersama!',
  'Jangan malu bertanya, saya siap membantu.',
  'Belajar dengan semangat, raih cita-cita.',
  'Buku dan teknologi, teman belajar terbaik.',
  'Saya ingin kamu terus semangat belajar.',
  'Ilmu pengetahuan memperluas cakrawala.',
  'Setiap buku adalah dunia baru untuk dijelajahi.',
  'Teknologi memudahkan akses ke informasi.',
  'Saya senang jika kamu suka membaca.',
  'Belajar adalah proses, nikmati setiap langkahnya.',
  'Buku adalah sumber kebijaksanaan.',
  'Teknologi membantu kita belajar lebih cepat.',
  'Saya selalu mendukungmu belajar.',
  'Jangan pernah puas dengan pengetahuan yang ada.',
  'Belajar bersama saya, belajar tanpa henti.',
  'Buku dan teknologi, teman sepanjang masa.',
  'Saya ingin kamu jadi orang sukses.',
  'Ilmu pengetahuan adalah investasi terbaik.',
  'Teknologi membuat belajar jadi menyenangkan.',
  'Saya selalu ada untuk membantu.',
  'Belajar adalah kunci membuka masa depan.',
  'Buku adalah sahabat sejati.',
  'Teknologi dan buku, kunci sukses belajar.',
  'Saya ingin kamu terus berkembang.',
  'Jangan takut mencoba hal baru.',
  'Belajar bersama saya, masa depan cerah.',
  'Buku adalah sumber inspirasi.',
  'Teknologi mempercepat pencapaian ilmu.',
  'Saya selalu semangat belajar.',
  'Belajar adalah perjalanan hidup.',
  'Buku dan teknologi, teman setia belajar.',
  'Saya ingin kamu jadi pembelajar hebat.',
  'Ilmu pengetahuan adalah cahaya kehidupan.',
  'Teknologi membuat belajar jadi efisien.',
  'Saya selalu mendukung impianmu.'
];
const quoteIndex = ref(0);
const currentQuote = ref(quotes[0]);
let synth = null;
let utter = null;
const speechEnabled = ref(false); // Default: suara OFF
let quoteAdvancing = false;
let muteIntervalId = null;
const isLoading = ref(false);
const isSpeaking = ref(false);

// Mulut animasi
const mouthCy = ref(135);
const mouthRx = ref(15);
const mouthRy = ref(6);
let mouthInterval = null;

watch(isSpeaking, (val) => {
  if (!val) {
    // Reset mulut ke posisi idle
    clearInterval(mouthInterval);
    mouthInterval = null;
    mouthRy.value = 6;
    mouthCy.value = 137;
  }
});
onBeforeUnmount(() => {
  if (mouthInterval) clearInterval(mouthInterval);
});

// Mata robot berkedip
const eyeRy = ref(13);
let blinkTimeout = null;
let blinkInterval = null;

function blink() {
  if (isLoading.value) return; // jangan berkedip saat loading
  eyeRy.value = 2;
  setTimeout(() => {
    eyeRy.value = 13;
    scheduleBlink();
  }, 120);
}
function scheduleBlink() {
  // Jadwalkan blink berikutnya secara acak 15-30 detik
  blinkTimeout = setTimeout(() => {
    blink();
  }, 15000 + Math.random() * 15000);
}
onMounted(() => {
  scheduleBlink();
});
onBeforeUnmount(() => {
  if (blinkTimeout) clearTimeout(blinkTimeout);
});

watch(isLoading, (val) => {
  if (!val) {
    scheduleBlink();
  }
});

const bodyFloatY = ref(0);
let bodyFloatInterval = null;
onMounted(() => {
  scheduleBlink();
  // Animasi badan naik turun
  let t = 0;
  bodyFloatInterval = setInterval(() => {
    t += 0.035;
    bodyFloatY.value = Math.sin(t) * 6;
  }, 32);
});
onBeforeUnmount(() => {
  if (blinkTimeout) clearTimeout(blinkTimeout);
  if (mouthInterval) clearInterval(mouthInterval);
  if (bodyFloatInterval) clearInterval(bodyFloatInterval);
});

function nextQuote() {
  let newIndex = quoteIndex.value;
  // Cari index random yang berbeda dari sebelumnya
  while (quotes.length > 1 && newIndex === quoteIndex.value) {
    newIndex = Math.floor(Math.random() * quotes.length);
  }
  quoteIndex.value = newIndex;
  currentQuote.value = quotes[quoteIndex.value];
  if (speechEnabled.value) {
    speakQuote(currentQuote.value);
  } else {
    muteIntervalId = setTimeout(nextQuote, 3000);
  }
}

function speakQuote(text) {
  if (!speechEnabled.value) return;
  if (!('speechSynthesis' in window)) return;
  if (synth && synth.speaking) synth.cancel();
  isLoading.value = true;
  isSpeaking.value = false;
  utter = new window.SpeechSynthesisUtterance(text);
  utter.lang = 'id-ID';
  utter.rate = 1.03;
  utter.pitch = 1.0;
  utter.volume = 1.0;
  utter.onstart = () => {
    isLoading.value = false;
    isSpeaking.value = true;
    // Mulai animasi mulut sinkron dengan suara
    mouthInterval = setInterval(() => {
      mouthRx.value = 11 + Math.random() * 6;
      mouthRy.value = 6 + Math.random() * 6;
      mouthCy.value = 141 + Math.random() * 4;
    }, 120);
  };
  utter.onend = () => {
    isSpeaking.value = false;
    clearInterval(mouthInterval);
    mouthInterval = null;
    setTimeout(nextQuote, 400); // jeda sebentar setelah selesai bicara
  };
  synth.speak(utter);
}

onMounted(() => {
  quoteAdvancing = true;
  // Mode mute: otomatis quote jalan tanpa suara
  muteIntervalId = setTimeout(nextQuote, 3000);
});
onBeforeUnmount(() => {
  quoteAdvancing = false;
  if (muteIntervalId) clearTimeout(muteIntervalId);
  if (synth && synth.speaking) synth.cancel();
});
function toggleSpeech() {
  speechEnabled.value = !speechEnabled.value;
  if (speechEnabled.value) {
    // Hentikan mute timer
    if (muteIntervalId) clearTimeout(muteIntervalId);
    // Mulai speech dari quote sekarang
    synth = window.speechSynthesis;
    speakQuote(currentQuote.value);
  } else {
    // Hentikan speech
    if (synth && synth.speaking) synth.cancel();
    isSpeaking.value = false;
    isLoading.value = false;
    // Mulai mute timer
    muteIntervalId = setTimeout(nextQuote, 3000);
  }
}

</script>

<style scoped>
.illustration {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2.5rem 1.2rem 1.2rem 1.2rem;
  min-width: 340px;
  min-height: 340px;
}

.indigo-bg-gradient {
  background: linear-gradient(135deg, #4f5bd5 0%, #fff 100%);
  border-radius: 2.2rem;
  box-shadow: 0 8px 40px 0 rgba(44, 62, 80, 0.10), 0 1.5px 0 #e5e8ef inset;
}

.robot-quote-bubble {
  background: #fff;
  color: #283e8a;
  font-size: 1.08rem;
  font-weight: 500;
  border-radius: 1.2em;
  box-shadow: 0 2px 18px 0 rgba(44, 62, 80, 0.10);
  padding: 1.1em 1.5em 1.1em 1.5em;
  margin: 1.1em auto 0 auto;
  max-width: 320px;
  min-height: 40px;
  position: relative;
  text-align: center;
  z-index: 2;
  transition: background 0.2s;
}

.robot-quote-bubble {
  min-height: 80px;
  height: 80px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.2s;
  /* padding, border-radius, shadow, dsb tetap seperti sebelumnya */
}

.robot-quote-bubble::after {
  content: '';
  position: absolute;
  bottom: -10px;
  left: 50%;
  transform: translateX(-50%);
  border-width: 12px 14px 0 14px;
  border-style: solid;
  border-color: #fff transparent transparent transparent;
  display: block;
}

.bubble-fade-enter-active,
.bubble-fade-leave-active {
  transition: opacity 0.5s, transform 0.5s;
}

.bubble-fade-enter-from,
.bubble-fade-leave-to {
  opacity: 0;
  transform: translateY(12px);
}

.bubble-fade-enter-to,
.bubble-fade-leave-from {
  opacity: 1;
  transform: translateY(0);
}

.illustration-caption {
  color: #283e8a;
  font-size: 1.08rem;
  font-weight: 600;
  margin-top: 1.4rem;
  text-align: center;
  letter-spacing: 0.01em;
  line-height: 1.4;
  opacity: 0.92;
}
</style>
