import {
  // convertUTCTimeToLocal,
  CookieUtils,
} from "../../utils";
import { STORE_ACTION_TYPES } from "../actions/storeContext.action";

export const initState = {
  language: CookieUtils.getCookie("language") || "vi",
  loading: false,
  cycles: [],
  mode: 2,
};

export const storeReducer = (state, action) => {
  const { type, payload } = action;
  switch (type) {
    case STORE_ACTION_TYPES.GET_LANGUAGE:
    case STORE_ACTION_TYPES.UPDATE_LANGUAGE: {
      CookieUtils.setCookie({ name: "language", value: payload, days: 365 });
      return { ...state, language: payload };
    }
    case STORE_ACTION_TYPES.GET_MODE:
    case STORE_ACTION_TYPES.UPDATE_MODE:
      return { ...state, mode: payload };
    case STORE_ACTION_TYPES.START_LOADING:
      return { ...state, loading: true };
    case STORE_ACTION_TYPES.END_LOADING:
      return { ...state, loading: false };
    case STORE_ACTION_TYPES.GET_CYCLES: {
      const next = payload || [];
      return {
        ...state,
        cycles: next.map((item) => ({
          ...item,
          // start: convertUTCTimeToLocal(item.start),
          // end: convertUTCTimeToLocal(item.end),
        })),
      };
    }
    case STORE_ACTION_TYPES.ADD_CYCLE:
      return {
        ...state,
        cycles: [
          ...state.cycles,
          {
            ...payload,
            // start: convertUTCTimeToLocal(payload.start),
            // end: convertUTCTimeToLocal(payload.end),
          },
        ],
      };
    case STORE_ACTION_TYPES.UPDATE_CYCLE: {
      const cycleId = payload.id;
      const findCycle = state.cycles.findIndex(({ id }) => id === cycleId);
      if (findCycle >= 0) {
        const nextCycles = [...state.cycles];
        nextCycles.splice(findCycle, 1, {
          ...payload,
          // start: convertUTCTimeToLocal(payload.start),
          // end: convertUTCTimeToLocal(payload.end),
        });
        return { ...state, cycles: nextCycles };
      } else {
        return state;
      }
    }
    case STORE_ACTION_TYPES.DELETE_CYCLE: {
      const cycleId = payload.id;
      const findCycle = state.cycles.findIndex(({ id }) => id === cycleId);
      if (findCycle >= 0) {
        const nextCycles = [...state.cycles];
        nextCycles.splice(findCycle, 1);
        return { ...state, cycles: nextCycles };
      } else {
        return state;
      }
    }
    default:
      return state;
  }
};
