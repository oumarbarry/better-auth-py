<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

// A plate photograph, not a sci-fi backdrop: hard points with real magnitude
// variance (cubed random => many faint, few bright) over three parallax depths.
const el = ref<HTMLCanvasElement>()
const DEPTHS = [
  { rate: 0.05, mag: 0.8, alpha: 0.5 },
  { rate: 0.13, mag: 1.2, alpha: 0.75 },
  { rate: 0.26, mag: 1.7, alpha: 1 },
]
const TINTS = ['#dce6ff', '#dce6ff', '#dce6ff', '#a8c4ff', '#51deec', '#ffd9b0']
let stars: { x: number; y: number; r: number; a: number; c: string; d: number }[] = []
let w = 0, h = 0, dpr = 1, raf = 0, lastY = -1
let stop = () => {}

function seed(canvas: HTMLCanvasElement) {
  dpr = Math.min(window.devicePixelRatio || 1, 2)
  w = canvas.clientWidth
  h = canvas.clientHeight
  canvas.width = Math.round(w * dpr)
  canvas.height = Math.round(h * dpr)
  // Density per area, so a phone does not pay for a 4K star count.
  const n = Math.min(420, Math.round((w * h) / 5200))
  stars = Array.from({ length: n }, () => {
    const d = Math.floor(Math.random() * DEPTHS.length)
    return {
      x: Math.random() * w,
      y: Math.random() * h * 2, // field is 2x tall: material for the parallax
      r: (0.35 + Math.random() ** 3 * 1.5) * DEPTHS[d].mag,
      a: (0.35 + Math.random() * 0.65) * DEPTHS[d].alpha,
      c: TINTS[(Math.random() * TINTS.length) | 0],
      d,
    }
  })
}

function draw(scrollY: number) {
  const ctx = el.value?.getContext('2d')
  if (!ctx) return
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  ctx.clearRect(0, 0, w, h)
  for (const s of stars) {
    const y = s.y - scrollY * DEPTHS[s.d].rate
    if (y < -4 || y > h + 4) continue
    ctx.globalAlpha = s.a
    ctx.fillStyle = s.c
    ctx.beginPath()
    ctx.arc(s.x, y, s.r, 0, 6.2832)
    ctx.fill()
  }
  ctx.globalAlpha = 1
}

onMounted(() => {
  const canvas = el.value
  if (!canvas) return
  const still = window.matchMedia('(prefers-reduced-motion: reduce)')
  const paint = () => {
    raf = 0
    const y = still.matches ? 0 : window.scrollY
    if (y === lastY) return
    lastY = y
    draw(y)
  }
  const schedule = () => {
    // Above 1.6 viewports the field has already faded out (see custom.css).
    if (!raf && window.scrollY < window.innerHeight * 1.6) raf = requestAnimationFrame(paint)
  }
  const reset = () => {
    seed(canvas)
    lastY = -1
    schedule()
  }
  // First paint off the critical path; the CSS nebula is already on screen.
  const idle = window.requestIdleCallback ?? ((cb: () => void) => setTimeout(cb, 1))
  idle(reset)
  window.addEventListener('resize', reset)
  if (!still.matches) window.addEventListener('scroll', schedule, { passive: true })
  stop = () => {
    cancelAnimationFrame(raf)
    window.removeEventListener('resize', reset)
    window.removeEventListener('scroll', schedule)
  }
})

onBeforeUnmount(() => stop())
</script>

<template>
  <div class="ba-sky" aria-hidden="true">
    <canvas ref="el" class="ba-sky-canvas" />
  </div>
</template>
