// 1. 发送 fetch 请求，获取前一次的数据
//
// 2. 根据当前数据的 hash 值，在前一次数据中寻找相同 hash 的数据
//
// 3. 找到后，计算加分，返回加分值

import { fetchVulnerData } from "./vulnerFetch";
import { type VulnerData, type DbVulnerability } from "./types";
import { vulnerPage } from "../../store";
import { get } from "svelte/store";

export async function getAssociationVulnScore(
  currentVulnNumber: number,
  hash: string,
): Promise<number> {
  if (currentVulnNumber <= 1) return 0;

  const targetNumber = currentVulnNumber - 1;

  try {
    // 1. 先从缓存拿，有就直接用（不发请求）
    let data;
    let cachedData = get(vulnerPage);
    if (cachedData && cachedData.has(targetNumber)) {
      data = cachedData.get(targetNumber);
    } else {
      // 2. 没有才发请求
      data = await fetchVulnerData(targetNumber);
      // 3. 存入缓存
      if (cachedData) cachedData.set(targetNumber, data);
    }

    // 4. 查找分数
    const found = data?.hasCWEVulns?.find((v) => v.hash === hash);
    return found ? found.score : 0;
  } catch (err) {
    console.warn("获取关联漏洞分数失败", err);
    return 0;
  }
}
