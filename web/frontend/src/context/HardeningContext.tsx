/* HardeningContext – global state via useReducer + Context API */

import {
    createContext,
    useContext,
    useReducer,
    useCallback,
    useEffect,
    type ReactNode,
} from "react";
import type { RuleItem, ResolveResult, GenerateResponse } from "../types";
import { fetchRules, resolveRules, generateConfig } from "../services/api";

// ── State & Actions ─────────────────────────────────────────────────────────

export type SelectedOS = "ubuntu" | "windows";

interface HardeningState {
    selectedOS: SelectedOS;
    rules: RuleItem[];
    sections: Record<string, RuleItem[]>;
    selectedRuleIds: Set<string>;
    validationResult: ResolveResult | null;
    isLoading: boolean;
    isResolving: boolean;
    isGenerating: boolean;
    generateResult: GenerateResponse | null;
    error: string | null;
    searchQuery: string;
    levelFilter: number | null;     // 1 or 2 or null = all
    automatedFilter: boolean | null; // true/false/null = all
}

type Action =
    | { type: "SET_OS"; os: SelectedOS }
    | { type: "SET_RULES"; rules: RuleItem[]; sections: Record<string, RuleItem[]> }
    | { type: "TOGGLE_RULE"; ruleId: string }
    | { type: "SELECT_ALL" }
    | { type: "CLEAR_ALL" }
    | { type: "SELECT_SECTION"; section: string }
    | { type: "SET_VALIDATION"; result: ResolveResult }
    | { type: "CLEAR_VALIDATION" }
    | { type: "SET_LOADING"; loading: boolean }
    | { type: "SET_RESOLVING"; resolving: boolean }
    | { type: "SET_GENERATING"; generating: boolean }
    | { type: "SET_GENERATE_RESULT"; result: GenerateResponse }
    | { type: "CLEAR_GENERATE_RESULT" }
    | { type: "SET_ERROR"; error: string | null }
    | { type: "SET_SEARCH"; query: string }
    | { type: "SET_LEVEL_FILTER"; level: number | null }
    | { type: "SET_AUTOMATED_FILTER"; automated: boolean | null };

const initialState: HardeningState = {
    selectedOS: "ubuntu",
    rules: [],
    sections: {},
    selectedRuleIds: new Set(),
    validationResult: null,
    isLoading: false,
    isResolving: false,
    isGenerating: false,
    generateResult: null,
    error: null,
    searchQuery: "",
    levelFilter: null,
    automatedFilter: null,
};

function reducer(state: HardeningState, action: Action): HardeningState {
    switch (action.type) {
        case "SET_OS":
            return {
                ...state,
                selectedOS: action.os,
                rules: [],
                sections: {},
                selectedRuleIds: new Set(),
                validationResult: null,
                generateResult: null,
                error: null,
                searchQuery: "",
            };

        case "SET_RULES":
            return {
                ...state,
                rules: action.rules,
                sections: action.sections,
                isLoading: false,
                error: null,
            };

        case "TOGGLE_RULE": {
            const next = new Set(state.selectedRuleIds);
            if (next.has(action.ruleId)) next.delete(action.ruleId);
            else next.add(action.ruleId);
            return { ...state, selectedRuleIds: next, validationResult: null, generateResult: null };
        }

        case "SELECT_ALL":
            return {
                ...state,
                selectedRuleIds: new Set(state.rules.map((r) => r.rule_id)),
                validationResult: null,
                generateResult: null,
            };

        case "CLEAR_ALL":
            return { ...state, selectedRuleIds: new Set(), validationResult: null, generateResult: null };

        case "SELECT_SECTION": {
            const next = new Set(state.selectedRuleIds);
            const sectionRules = state.sections[action.section] || [];
            const allSelected = sectionRules.every((r) => next.has(r.rule_id));
            sectionRules.forEach((r) => {
                if (allSelected) next.delete(r.rule_id);
                else next.add(r.rule_id);
            });
            return { ...state, selectedRuleIds: next, validationResult: null, generateResult: null };
        }

        case "SET_VALIDATION":
            return { ...state, validationResult: action.result, isResolving: false };

        case "CLEAR_VALIDATION":
            return { ...state, validationResult: null };

        case "SET_LOADING":
            return { ...state, isLoading: action.loading };

        case "SET_RESOLVING":
            return { ...state, isResolving: action.resolving };

        case "SET_GENERATING":
            return { ...state, isGenerating: action.generating };

        case "SET_GENERATE_RESULT":
            return { ...state, generateResult: action.result, isGenerating: false };

        case "CLEAR_GENERATE_RESULT":
            return { ...state, generateResult: null };

        case "SET_ERROR":
            return { ...state, error: action.error, isLoading: false, isResolving: false, isGenerating: false };

        case "SET_SEARCH":
            return { ...state, searchQuery: action.query };

        case "SET_LEVEL_FILTER":
            return { ...state, levelFilter: action.level };

        case "SET_AUTOMATED_FILTER":
            return { ...state, automatedFilter: action.automated };

        default:
            return state;
    }
}

// ── Context ─────────────────────────────────────────────────────────────────

interface HardeningContextValue {
    state: HardeningState;
    setOS: (os: SelectedOS) => void;
    toggleRule: (ruleId: string) => void;
    selectAll: () => void;
    clearAll: () => void;
    selectSection: (section: string) => void;
    runResolve: () => Promise<void>;
    runGenerate: () => Promise<void>;
    setSearch: (query: string) => void;
    setLevelFilter: (level: number | null) => void;
    setAutomatedFilter: (automated: boolean | null) => void;
}

const HardeningContext = createContext<HardeningContextValue | null>(null);

// ── Provider ────────────────────────────────────────────────────────────────

export function HardeningProvider({ children }: { children: ReactNode }) {
    const [state, dispatch] = useReducer(reducer, initialState);

    // Load rules whenever the OS changes
    useEffect(() => {
        let cancelled = false;

        async function load() {
            dispatch({ type: "SET_LOADING", loading: true });
            dispatch({ type: "SET_ERROR", error: null });
            try {
                const data = await fetchRules(state.selectedOS);
                if (cancelled) return;

                const allRules: RuleItem[] = [];
                Object.values(data.sections).forEach((arr) => allRules.push(...arr));
                dispatch({ type: "SET_RULES", rules: allRules, sections: data.sections });
            } catch (err: unknown) {
                if (cancelled) return;
                const msg = err instanceof Error ? err.message : "Kurallar yüklenemedi";
                dispatch({ type: "SET_ERROR", error: msg });
            }
        }
        load();
        return () => { cancelled = true; };
    }, [state.selectedOS]);

    const setOS = useCallback((os: SelectedOS) => dispatch({ type: "SET_OS", os }), []);
    const toggleRule = useCallback((id: string) => dispatch({ type: "TOGGLE_RULE", ruleId: id }), []);
    const selectAll = useCallback(() => dispatch({ type: "SELECT_ALL" }), []);
    const clearAll = useCallback(() => dispatch({ type: "CLEAR_ALL" }), []);
    const selectSection = useCallback((s: string) => dispatch({ type: "SELECT_SECTION", section: s }), []);
    const setSearch = useCallback((q: string) => dispatch({ type: "SET_SEARCH", query: q }), []);
    const setLevelFilter = useCallback((l: number | null) => dispatch({ type: "SET_LEVEL_FILTER", level: l }), []);
    const setAutomatedFilter = useCallback((a: boolean | null) => dispatch({ type: "SET_AUTOMATED_FILTER", automated: a }), []);

    const runResolve = useCallback(async () => {
        if (state.selectedRuleIds.size === 0) return;
        dispatch({ type: "SET_RESOLVING", resolving: true });
        try {
            const result = await resolveRules(
                state.selectedOS,
                Array.from(state.selectedRuleIds)
            );
            dispatch({ type: "SET_VALIDATION", result });
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : "Doğrulama hatası";
            dispatch({ type: "SET_ERROR", error: msg });
        }
    }, [state.selectedOS, state.selectedRuleIds]);

    const runGenerate = useCallback(async () => {
        if (state.selectedRuleIds.size === 0) return;
        dispatch({ type: "SET_GENERATING", generating: true });
        try {
            const fmt = state.selectedOS === "ubuntu" ? "ansible" : "powershell";
            const result = await generateConfig(
                state.selectedOS,
                Array.from(state.selectedRuleIds),
                fmt
            );
            dispatch({ type: "SET_GENERATE_RESULT", result });
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : "Oluşturma hatası";
            dispatch({ type: "SET_ERROR", error: msg });
        }
    }, [state.selectedOS, state.selectedRuleIds]);

    return (
        <HardeningContext.Provider
            value={{
                state,
                setOS,
                toggleRule,
                selectAll,
                clearAll,
                selectSection,
                runResolve,
                runGenerate,
                setSearch,
                setLevelFilter,
                setAutomatedFilter,
            }}
        >
            {children}
        </HardeningContext.Provider>
    );
}

// ── Hook ────────────────────────────────────────────────────────────────────

export function useHardening(): HardeningContextValue {
    const ctx = useContext(HardeningContext);
    if (!ctx) throw new Error("useHardening must be used within HardeningProvider");
    return ctx;
}
