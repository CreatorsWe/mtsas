import { writable } from "svelte/store";
import { type TimestampMap, type VulnerData } from "./routes/utils/types";

export const currentTimestamp = writable<TimestampMap | null>(null);

export const vulnerPage = writable<Map<number, VulnerData> | null>(null);
