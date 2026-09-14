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
          // Backgrounds
          bg:       '#0F172A',   // dark base
          surface:  '#1E293B',   // cards, panels, modals
          border:   '#334155',   // subtle borders

          // Accent
          accent:   '#3B82F6',   // buttons, active states, links

          // Risk tiers
          critical: '#EF4444',   // ≥85
          high:     '#F97316',   // 60-84
          suspicious:'#F59E0B',  // 30-59
          safe:     '#10B981',   // 0-29

          // LIME
          malicious:'#DC2626',   // sentence highlight — threat
          benign:   '#16A34A',   // sentence highlight — safe

          // Text
          text:     '#F8FAFC',   // headings, labels, badges
          muted:    '#94A3B8',   // timestamps, metadata, footnotes
        },
      },

      fontFamily: {
        sans: ['Inter', 'SF Pro Display', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },

      fontSize: {
        xs:   ['11px', '1.5'],
        sm:   ['13px', '1.5'],
        base: ['14px', '1.5'],
        lg:   ['16px', '1.4'],
        xl:   ['20px', '1.3'],
        '2xl':['24px', '1.2'],
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

