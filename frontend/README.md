# EncodeLab Frontend

A modern React-based frontend for the EncodeLab encryption and benchmarking tool.

## Features

- **Algorithm Selection**: Choose from multiple encryption algorithms (AES-GCM, AES-CBC, ChaCha20, DES, TripleDES, RSA-OAEP)
- **Text & File Input**: Support for both text input and file uploads with drag & drop
- **Real-time Processing**: Encrypt/decrypt data with live performance metrics
- **Performance Visualization**: Interactive charts showing execution time and memory usage
- **Operation History**: Track and compare performance across different algorithms
- **Responsive Design**: Mobile-friendly interface built with Tailwind CSS

## Tech Stack

- **React 18** - Modern React with hooks
- **Vite** - Fast build tool and dev server
- **Tailwind CSS** - Utility-first CSS framework
- **Recharts** - Composable charting library
- **Lucide React** - Beautiful icons
- **Axios** - HTTP client for API communication

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Backend API server running on port 5000

### Installation

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm run dev
```

3. Open your browser and navigate to `http://localhost:3000`

### Build for Production

```bash
npm run build
```

The built files will be in the `dist` directory.

## Project Structure

```
src/
├── components/          # React components
│   ├── AlgorithmSelector.jsx
│   ├── InputForm.jsx
│   ├── BenchmarkPanel.jsx
│   └── BenchmarkChart.jsx
├── services/           # API and external services
│   └── api.js
├── App.jsx            # Main application component
├── main.jsx           # Application entry point
└── index.css          # Global styles
```

## API Integration

The frontend communicates with the backend API through the `cryptoAPI` service:

- `POST /api/encrypt` - Encrypt data
- `POST /api/decrypt` - Decrypt data
- `GET /api/algorithms` - Get supported algorithms
- `GET /api/history` - Get operation history
- `GET /api/benchmarks` - Get performance benchmarks

## Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

### Code Style

This project uses ESLint for code linting. The configuration is in `.eslintrc.cjs`.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details 