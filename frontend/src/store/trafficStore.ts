import { create } from 'zustand';
import type { HTTPTraffic, TrafficFilter } from '../types';
import apiService from '../services/api';

interface TrafficState {
  traffic: HTTPTraffic[];
  currentTraffic: HTTPTraffic | null;
  isLoading: boolean;
  error: string | null;

  // Filters
  filters: TrafficFilter;

  // Actions
  fetchTraffic: (subdomainId: number, filters?: TrafficFilter) => Promise<void>;
  fetchTrafficById: (id: number) => Promise<void>;
  searchTraffic: (domainId: number, query: string) => Promise<void>;
  setFilters: (filters: Partial<TrafficFilter>) => void;
  clearFilters: () => void;
  clearError: () => void;
}

export const useTrafficStore = create<TrafficState>((set, get) => ({
  traffic: [],
  currentTraffic: null,
  isLoading: false,
  error: null,

  filters: {},

  fetchTraffic: async (subdomainId: number, filters?: TrafficFilter) => {
    set({ isLoading: true, error: null });
    try {
      const traffic = await apiService.getTraffic(subdomainId, filters);
      set({ traffic, isLoading: false });
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  fetchTrafficById: async (id: number) => {
    set({ isLoading: true, error: null });
    try {
      const traffic = await apiService.getTrafficById(id);
      set({ currentTraffic: traffic, isLoading: false });
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  searchTraffic: async (domainId: number, query: string) => {
    set({ isLoading: true, error: null });
    try {
      const traffic = await apiService.searchTraffic(domainId, query);
      set({ traffic, isLoading: false });
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  setFilters: (filters) => {
    set((state) => ({
      filters: { ...state.filters, ...filters },
    }));
  },

  clearFilters: () => set({ filters: {} }),

  clearError: () => set({ error: null }),
}));
