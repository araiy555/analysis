/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        dark: {
          900: '#0a0d14',
          800: '#0f1117',
          700: '#161b22',
          600: '#1c2230',
          500: '#21262d',
          400: '#30363d',
        },
        accent: {
          green: '#39d353',
          red: '#f85149',
          orange: '#f0883e',
          blue: '#58a6ff',
          purple: '#bc8cff',
          cyan: '#56d364',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
