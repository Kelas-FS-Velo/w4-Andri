<template>
  <canvas ref="canvas" class="fixed top-0 left-0 w-full h-full pointer-events-none opacity-70 z-50"></canvas>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue';

const canvas = ref(null);
let ctx, width, height, snowflakes, animationId;
const snowCount = 60;

function resize() {
  width = window.innerWidth;
  height = window.innerHeight;
  if (canvas.value) {
    canvas.value.width = width;
    canvas.value.height = height;
  }
}

function createSnowflake() {
  return {
    x: Math.random() * width,
    y: Math.random() * -height,
    r: 2 + Math.random() * 4,
    d: 1 + Math.random() * 1.5,
    opacity: 0.6 + Math.random() * 0.4,
    drift: Math.random() * 2 - 1
  };
}

function draw() {
  ctx.clearRect(0, 0, width, height);
  ctx.save();
  ctx.globalAlpha = 0.8;
  for (let i = 0; i < snowflakes.length; i++) {
    let f = snowflakes[i];
    ctx.beginPath();
    ctx.arc(f.x, f.y, f.r, 0, 2 * Math.PI);
    ctx.fillStyle = `rgba(200,220,255,${f.opacity})`;
    ctx.shadowColor = '#b3e0ff';
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.closePath();
  }
  ctx.restore();
}

function update() {
  for (let i = 0; i < snowflakes.length; i++) {
    let f = snowflakes[i];
    f.y += f.d;
    f.x += f.drift * 0.3;
    if (f.y > height + f.r) {
      snowflakes[i] = createSnowflake();
      snowflakes[i].y = -f.r;
    }
    if (f.x < 0) f.x = width;
    if (f.x > width) f.x = 0;
  }
}

function animate() {
  draw();
  update();
  animationId = requestAnimationFrame(animate);
}

function start() {
  resize();
  snowflakes = [];
  for (let i = 0; i < snowCount; i++) {
    snowflakes.push(createSnowflake());
  }
  animate();
}

onMounted(() => {
  if (!canvas.value) return;
  ctx = canvas.value.getContext('2d');
  window.addEventListener('resize', resize);
  start();
});

onUnmounted(() => {
  window.removeEventListener('resize', resize);
  if (animationId) cancelAnimationFrame(animationId);
});
</script>
