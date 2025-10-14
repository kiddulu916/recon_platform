# Reconnaissance Platform - Frontend

Modern React + TypeScript web interface for the Security Reconnaissance Platform.

## Tech Stack

- **React 19** - UI framework
- **TypeScript** - Type safety
- **Vite 7** - Build tool and dev server
- **Tailwind CSS v4** - Styling (requires @tailwindcss/postcss)
- **Zustand** - State management
- **React Router** - Routing
- **TanStack Query** - Server state management
- **Axios** - HTTP client
- **D3.js & Cytoscape.js** - Data visualization
- **Recharts** - Charts

## Getting Started

### Prerequisites

- **Node.js 20.19+ or 22+** (LTS recommended) - Vite 7 requirement
  - Check version: `node --version`
  - Install via [nvm](https://github.com/nvm-sh/nvm): `nvm install 22 && nvm use 22`
  - Or see `.nvmrc` file for required version
- **npm 10+**
- Backend API running on `http://localhost:8000`

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The application will be available at `http://localhost:3000`.

### Build for Production

```bash
npm run build
```

## Project Structure

```
src/
├── components/       # Reusable UI components
│   ├── common/       # Common components (Button, Card, Badge, etc.)
│   ├── dashboard/    # Dashboard-specific components
│   ├── traffic/      # HTTP traffic components
│   ├── vulnerabilities/ # Vulnerability management components
│   └── patterns/     # Pattern recognition components
├── pages/            # Page components
├── services/         # API and WebSocket services
├── store/            # Zustand state management
├── types/            # TypeScript type definitions
├── utils/            # Utility functions
└── hooks/            # Custom React hooks
```

## Features

### Real-Time Scanning Dashboard
- Live scan progress tracking
- WebSocket-based real-time updates
- Subdomain discovery feed
- Vulnerability detection alerts

### Infrastructure Visualization
- Force-directed graph visualization
- Interactive node exploration
- Risk-based color coding
- Relationship mapping

### HTTP Traffic Explorer
- Advanced filtering and search
- Request/response inspection
- Syntax highlighting
- Pattern highlighting for vulnerabilities

### Vulnerability Management
- Multi-dimensional filtering
- Verification workflow
- False positive tracking
- Exploit matching and risk scoring

### Pattern Recognition
- Vulnerability chaining visualization
- Attack graph exploration
- Temporal, spatial, and behavioral patterns
- Exploitation scenario generation

## Environment Configuration

Create a `.env` file in the frontend directory:

```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

## Development Guidelines

- Use functional components with hooks
- Prefer composition over inheritance
- Use TypeScript strictly - no `any` types
- Follow the existing code style
- Write meaningful component and variable names
- Keep components small and focused
- Use Zustand for global state, local state for component-specific data
- Use TanStack Query for server state management

## API Integration

The frontend communicates with the backend through:

1. **REST API** (`/api/*`) - Standard CRUD operations
2. **WebSocket** (`/ws`) - Real-time updates during scanning

All API calls are handled through the `apiService` in `src/services/api.ts`.
WebSocket connections are managed through `wsService` in `src/services/websocket.ts`.

## State Management

- **Domain Store** - Domain and subdomain management
- **Scan Store** - Scan job and progress tracking
- **Vulnerability Store** - Vulnerability data and filters
- **Traffic Store** - HTTP traffic and search

## Contributing

When adding new features:

1. Create TypeScript types in `src/types/`
2. Add API methods to `src/services/api.ts`
3. Create Zustand store if needed
4. Build reusable components in `src/components/`
5. Add pages to `src/pages/` and routes to `App.tsx`

## License

This is a defensive security tool for authorized testing only.
