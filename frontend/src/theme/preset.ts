import { definePreset } from '@primeuix/themes'
import Aura from '@primeuix/themes/aura'

// Linear-like preset: violet primary, surfaces mapped to our tokens.
export const VaulTLSPreset = definePreset(Aura, {
  semantic: {
    primary: {
      50:'#f2effb',100:'#e3dcf7',200:'#c8baef',300:'#ac97e6',400:'#9175de',
      500:'#6e56cf',600:'#5d47b8',700:'#4c3a97',800:'#3a2d74',900:'#2a2154',950:'#1a1436',
    },
    colorScheme: {
      dark: {
        surface: { 0:'#ffffff', 50:'#e6e8ee', 100:'#cbd0db', 200:'#9ca3b4',
          300:'#7c8190', 400:'#5b606e', 500:'#3a3f4b', 600:'#272b34',
          700:'#181b22', 800:'#11131a', 900:'#0e1016', 950:'#0b0d12' },
      },
    },
  },
})
