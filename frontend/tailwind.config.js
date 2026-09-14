/** @type {import('tailwindcss').Config} */
export default {
  // Dark mode via class so we can toggle it at runtime
  darkMode: 'class',

  content: [
    './index.html',
    './src/**/*.{js,jsx,ts,tsx}',
  ],

  theme: {
    extend: {
      // ── MailForenSIX colour palette (from UX_Dev.md) ────────────────────────
      colors: {
        mfx: {
          // Themed via CSS custom properties (see index.css)
          bg:         'var(--mfx-bg)',
          surface:    'var(--mfx-surface)',
          border:     'var(--mfx-border)',
          text:       'var(--mfx-text)',
          muted:      'var(--mfx-muted)',
          accent:     'var(--mfx-accent)',

          // Risk tiers — fixed regardless of theme
          critical:   '#EF4444',
          high:       '#F97316',
          suspicious: '#F59E0B',
          safe:       '#10B981',
          malicious:  '#DC2626',
          benign:     '#16A34A',
        },
      },

      fontFamily: {
        sans: ['Inter', 'SF Pro Display', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },

      fontSize: {
        xs:   ['12px', '1.5'],
        sm:   ['14px', '1.5'],
        base: ['16px', '1.6'],
        lg:   ['18px', '1.5'],
        xl:   ['22px', '1.3'],
        '2xl':['28px', '1.2'],
        '3xl':['36px', '1.1'],
        '4xl':['42px', '1.1'],
        '6xl':['60px', '1'],
      },

      borderRadius: {
        panel: '10px',
        badge: '6px',
      },

      boxShadow: {
        panel: '0 4px 24px 0 rgba(0,0,0,0.35)',
        glow:  '0 0 16px rgba(59,130,246,0.4)',
      },

      animation: {
        'gauge-fill': 'gaugeFill 0.3s ease-out forwards',
        'fade-in':    'fadeIn 0.2s ease-out',
        'slide-up':   'slideUp 0.25s ease-out',
        'pulse-dot':  'pulseDot 1.5s ease-in-out infinite',
      },

      keyframes: {
        gaugeFill: {
          from: { width: '0%' },
          to:   { width: 'var(--gauge-width)' },
        },
        fadeIn: {
          from: { opacity: 0 },
          to:   { opacity: 1 },
        },
        slideUp: {
          from: { opacity: 0, transform: 'translateY(8px)' },
          to:   { opacity: 1, transform: 'translateY(0)' },
        },
        pulseDot: {
          '0%, 100%': { opacity: 1 },
          '50%':      { opacity: 0.3 },
        },
      },
    },
  },

  plugins: [],
}

