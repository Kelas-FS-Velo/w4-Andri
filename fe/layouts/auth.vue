<template>
  <div class="auth-layout">
    <div class="auth-container">
      <div class="auth-left">
        <slot />
      </div>
      <div class="auth-right">
        <!-- Illustration: Robot Holding Book -->
        <RobotIllustration />

      </div>
    </div>
  </div>
</template>

<script setup>
</script>

<style scoped>
.auth-layout {
  min-height: 100vh;
  min-width: 100vw;
  width: 100vw;
  height: 100vh;
  display: flex;
  align-items: stretch;
  justify-content: stretch;
  /* Subtle background pattern */
  background: linear-gradient(135deg, #f5f6fa 80%, #eaf6fb 100%),
    url('data:image/svg+xml;utf8,<svg width="40" height="40" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="20" cy="20" r="1.5" fill="%23aed6f1" fill-opacity="0.14"/></svg>');
  background-size: cover, 80px 80px;
  background-repeat: repeat;
}


.auth-container {
  display: flex;
  flex-direction: row;
  width: 100vw;
  height: 100vh;
  max-width: 100vw;
  max-height: 100vh;
  background: #fff;
  border-radius: 0;
  box-shadow: none;
  overflow: hidden;
}

.auth-left {
  flex: 1 1 0%;
  min-width: 340px;
  min-height: 100vh;
  height: 100vh;
  padding: 3.5rem 2.8rem;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 8px 40px 0 rgba(44,62,80,0.10), 0 1.5px 0 #e5e8ef inset;
  border-right: 1.5px solid #eaf0f8;
  position: relative;
  z-index: 2;
  transition: box-shadow 0.2s;
  background-color: rgba(197, 197, 197, 0.1);
  padding: 3.5rem 2.8rem;
}
.auth-left::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  border-radius: 2.2rem 0 0 2.2rem;
  pointer-events: none;
  box-shadow: 0 2px 24px 0 rgba(44,62,80,0.06);
  opacity: 0.6;
  z-index: 1;
}


.auth-right {
  flex: 1 1 0%;
  min-width: 320px;
  background: linear-gradient(135deg, #eaf6fb 0%, #aed6f1 60%, #f9e79f 100%);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  position: relative;
  border-radius: 0 2.2rem 2.2rem 0;
  box-shadow: 0 8px 40px 0 rgba(44,62,80,0.08);
}


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
  box-shadow: 0 8px 40px 0 rgba(44,62,80,0.10), 0 1.5px 0 #e5e8ef inset;
}

.robot-quote-bubble {
  background: #fff;
  color: #283e8a;
  font-size: 1.08rem;
  font-weight: 500;
  border-radius: 1.2em;
  box-shadow: 0 2px 18px 0 rgba(44,62,80,0.10);
  padding: 1.1em 1.5em 1.1em 1.5em;
  margin: 1.1em auto 0 auto;
  max-width: 320px;
  min-height: 40px;
  position: relative;
  text-align: center;
  z-index: 2;
  transition: background 0.2s;
}
.robot-quote-bubble::after {
  content: '';
  position: absolute;
  bottom: -18px;
  left: 50%;
  transform: translateX(-50%);
  border-width: 12px 14px 0 14px;
  border-style: solid;
  border-color: #fff transparent transparent transparent;
  display: block;
}
.bubble-fade-enter-active, .bubble-fade-leave-active {
  transition: opacity 0.5s, transform 0.5s;
}
.bubble-fade-enter-from, .bubble-fade-leave-to {
  opacity: 0;
  transform: translateY(12px);
}
.bubble-fade-enter-to, .bubble-fade-leave-from {
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

.illustration svg {
  width: 420px;
  height: 340px;
  max-width: 90vw;
  max-height: 45vh;
  display: block;
  margin: 0 auto;
  filter: drop-shadow(0 6px 32px rgba(44, 62, 80, 0.13));
  transition: transform 0.2s;
}

.illustration svg:hover {
  transform: scale(1.03) rotate(-1deg);
  filter: drop-shadow(0 12px 40px rgba(44, 62, 80, 0.18));
}

@media (max-width: 900px) {
  .illustration svg {
    width: 85vw;
    height: 180px;
    max-height: 25vh;
  }
}

.illustration-caption {
  margin-top: 1rem;
  color: #2874a6;
  font-size: 1.1rem;
  text-align: center;
  font-weight: 500;
}

@media (max-width: 900px) {
  .auth-container {
    flex-direction: column-reverse;
    width: 98vw;
    min-width: unset;
  }

  .auth-left,
  .auth-right {
    min-width: unset;
    width: 100%;
    padding: 2rem 1.5rem;
    border-radius: 1.2rem !important;
    box-shadow: none !important;
  }
  .auth-container::before {
    display: none;
  }
  .illustration svg {
    width: 85vw;
    height: 180px;
    max-height: 25vh;
  }
}

@media (max-width: 900px) {
  .auth-left, .auth-right {
    min-width: unset;
    width: 100%;
    padding: 2rem 1.5rem;
    border-radius: 1.2rem !important;
    box-shadow: none !important;
  }
  .auth-container::before {
    display: none;
  }
  .illustration svg {
    width: 85vw;
    height: 180px;
    max-height: 25vh;
  }
}

</style>
