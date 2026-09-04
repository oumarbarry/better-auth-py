import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import { h } from 'vue'
import { useData } from 'vitepress'
import Starfield from './Starfield.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  Layout() {
    const { frontmatter } = useData()
    return h(DefaultTheme.Layout, null, {
      // The sky belongs to the landing fold only; docs pages stay a reading surface.
      'layout-top': () => (frontmatter.value.layout === 'home' ? h(Starfield) : null),
    })
  },
} satisfies Theme
