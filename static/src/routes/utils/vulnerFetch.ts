import type { VulnerData } from "./types.ts";

const API_BASE = "http://localhost:8080";

export async function fetchVulnerData(number: number): Promise<VulnerData> {
  const res = await fetch(`${API_BASE}/mtsas/vulner-data?number=${number}`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  });

  if (!res.ok) {
    throw new Error(`请求失败：${res.status}`);
  }

  return res.json();
}
