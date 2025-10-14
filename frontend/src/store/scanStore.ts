import { create } from 'zustand';
import type { ScanJob, ScanProgress, ScanResults } from '../types';
import apiService from '../services/api';
import wsService from '../services/websocket';

interface ScanState {
  scans: ScanJob[];
  currentScan: ScanJob | null;
  scanProgress: ScanProgress | null;
  scanResults: ScanResults | null;
  isLoading: boolean;
  error: string | null;

  // Actions
  fetchScans: (domainId?: number) => Promise<void>;
  fetchScan: (jobId: number) => Promise<void>;
  startScan: (data: { domain_id: number; scan_type: string; enable_recursion?: boolean }) => Promise<ScanJob>;
  cancelScan: (jobId: number) => Promise<void>;
  fetchScanResults: (jobId: number) => Promise<void>;
  updateScanProgress: (progress: ScanProgress) => void;
  clearError: () => void;
}

export const useScanStore = create<ScanState>((set, get) => ({
  scans: [],
  currentScan: null,
  scanProgress: null,
  scanResults: null,
  isLoading: false,
  error: null,

  fetchScans: async (domainId?: number) => {
    set({ isLoading: true, error: null });
    try {
      const scans = await apiService.getScanJobs(domainId);
      set({ scans, isLoading: false });
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  fetchScan: async (jobId: number) => {
    set({ isLoading: true, error: null });
    try {
      const scan = await apiService.getScanJob(jobId);
      set({ currentScan: scan, isLoading: false });
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  startScan: async (data) => {
    set({ isLoading: true, error: null });
    try {
      const scan = await apiService.startScan(data);
      set((state) => ({
        scans: [...state.scans, scan],
        currentScan: scan,
        isLoading: false,
      }));
      return scan;
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
      throw error;
    }
  },

  cancelScan: async (jobId: number) => {
    set({ isLoading: true, error: null });
    try {
      await apiService.cancelScan(jobId);
      set((state) => ({
        scans: state.scans.map((s) =>
          s.id === jobId ? { ...s, status: 'cancelled' as const } : s
        ),
        isLoading: false,
      }));
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  fetchScanResults: async (jobId: number) => {
    set({ isLoading: true, error: null });
    try {
      const results = await apiService.getScanResults(jobId);
      set({ scanResults: results, isLoading: false });
    } catch (error: any) {
      set({ error: error.message, isLoading: false });
    }
  },

  updateScanProgress: (progress: ScanProgress) => {
    set({ scanProgress: progress });
    // Also update the scan in the list if it exists
    set((state) => ({
      scans: state.scans.map((s) =>
        s.id === progress.job_id
          ? {
              ...s,
              status: progress.status,
              current_phase: progress.current_phase,
              progress_percentage: progress.progress_percentage,
              errors: progress.errors,
              warnings: progress.warnings,
            }
          : s
      ),
      currentScan:
        state.currentScan?.id === progress.job_id
          ? {
              ...state.currentScan,
              status: progress.status,
              current_phase: progress.current_phase,
              progress_percentage: progress.progress_percentage,
              errors: progress.errors,
              warnings: progress.warnings,
            }
          : state.currentScan,
    }));
  },

  clearError: () => set({ error: null }),
}));
