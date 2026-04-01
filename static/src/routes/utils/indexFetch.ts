import { type TimestampMap } from "./types";

const INDEXDATA_ADDRESS = "http://localhost:8080/mtsas/index-data/timestamps";
// 向 /mtsas/index-data/timestamps 发送请求

export interface IndexData {
    projectName: string;
    timestampMaps: Array<TimestampMap>;
}

export async function fetchIndexData(): Promise<IndexData> {
    // 发送 GET 请求到指定接口
    const response = await fetch(INDEXDATA_ADDRESS, {
        method: "GET",
        // 可根据后端要求配置请求头
        headers: {
            "Content-Type": "application/json",
        },
        // 跨域/凭证配置（按需开启）
        // credentials: 'include',
    });

    // 检查响应状态
    if (!response.ok) {
        throw new Error(`请求失败，状态码：${response.status}`);
    }

    return response.json();
}
