import { create } from 'zustand';
import type { Domain, Subdomain } from '../types';
import apiService from '../services/api';

interface DomainState {
  domains: Domain[];
  currentDomain: Domain | null;
  subdomains: Subdomain[];
  isLoading: boolean;
  error: string | null;

  // Actions
  fetchDomains: () => Promise<void>;
  fetchDomain: (id: number) => Promise<void>;
  createDomain: (data: { domain: string; is_authorized: boolean; scan_profile?: string }) => Promise<Domain>;
  deleteDomain: (id: number) => Promise<void>;
  fetchSubdomains: (domainId: number) => Promise<void>;
  setCurrentDomain: (domain: Domain | null) => void;
  clearError: () => void;
}

export const useDomainStore = create<DomainState>((set, get) => ({
  domains: [],
  currentDomain: null,
  subdomains: [],
  isLoading: false,
  error: null,

  fetchDomains: async () => {
    set({ isLoading: true, error: null });
    try {
      const domains = await apiService.getDomains();
      set({ domains, isLoading: false });
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  fetchDomain: async (id: number) => {
    set({ isLoading: true, error: null });
    try {
      const domain = await apiService.getDomain(id);
      set({ currentDomain: domain, isLoading: false });
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  createDomain: async (data) => {
    set({ isLoading: true, error: null });
    try {
      const domain = await apiService.createDomain(data);
      set((state) => ({
        domains: [...state.domains, domain],
        isLoading: false,
      }));
      return domain;
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
      throw error;
    }
  },

  deleteDomain: async (id: number) => {
    set({ isLoading: true, error: null });
    try {
      await apiService.deleteDomain(id);
      set((state) => ({
        domains: state.domains.filter((d) => d.id !== id),
        currentDomain: state.currentDomain?.id === id ? null : state.currentDomain,
        isLoading: false,
      }));
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  fetchSubdomains: async (domainId: number) => {
    set({ isLoading: true, error: null });
    try {
      const subdomains = await apiService.getSubdomains(domainId);
      set({ subdomains, isLoading: false });
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  setCurrentDomain: (domain) => set({ currentDomain: domain }),

  clearError: () => set({ error: null }),
}));
