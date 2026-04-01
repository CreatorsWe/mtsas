import { writable } from "svelte/store";
import { type TimestampMap } from "./routes/utils/types";

export const currentTimestamp = writable<TimestampMap | null>(null);
