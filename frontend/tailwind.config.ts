import type { Config } from 'tailwindcss'
import primeui from 'tailwindcss-primeui'
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{vue,ts}'],
  plugins: [primeui],
} satisfies Config
