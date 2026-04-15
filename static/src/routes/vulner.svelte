<script lang="ts">
    import { currentTimestamp } from "../store";
    import { onMount } from "svelte";
    import { vulnerPage } from "../store";
    import { getAssociationVulnScore } from "./utils/association_score";
    import {
        type VulnerData,
        type DbVulnerability,
        type SeverityLevel,
        type ConfidenceLevel,
    } from "./utils/types";
    import { fetchVulnerData } from "./utils/vulnerFetch";

    let vulnerData: VulnerData | null = null;
    let currentNumber: number;
    let currenttimestamp: string;
    let activeTab = "hash";
    let sort_flag = "0";
    let sortedHashVulns: DbVulnerability[] = [];
    let sortedEmptyHashVulns: DbVulnerability[] = [];

    let showCweModal = false;
    let currentEditItem: DbVulnerability | null = null;
    let cweInputValue = "";

    // ==============================
    // 修复：关联排序真正生效
    // ==============================
    async function sortVulns(
        list: DbVulnerability[],
        sort_flag: string,
    ): Promise<DbVulnerability[]> {
        if (!list || list.length === 0) return [];

        // 1. 深克隆，保证 Svelte 能检测到变化
        const vulnsClone = list.map((item) => ({
            ...item,
            final_score: item.score, // 默认等于自身分数
        }));

        // 模式0：仅按当前分数
        if (sort_flag === "0") {
            return vulnsClone.sort((a, b) => b.final_score - a.final_score);
        }

        // 模式1：关联加权排序（真正生效版）
        if (sort_flag === "1") {
            const scoreMap = new Map<string, number>();

            // 批量获取历史分数（缓存防重复请求）
            for (const item of vulnsClone) {
                if (item.hash && !scoreMap.has(item.hash)) {
                    const prevScore = await getAssociationVulnScore(
                        currentNumber,
                        item.hash,
                    );
                    scoreMap.set(item.hash, prevScore);
                }
            }

            // 计算加权 final_score
            for (const item of vulnsClone) {
                const prevScore = scoreMap.get(item.hash) || 0;
                const weight = 0.4; // 权重可调
                item.final_score = Math.max(
                    1,
                    Math.min(10, item.score + prevScore * weight),
                );
            }

            // 按最终分数排序
            return vulnsClone.sort((a, b) => b.final_score - a.final_score);
        }

        return vulnsClone;
    }

    // ==============================
    // 切换排序触发重排
    // ==============================
    async function handleSortChange() {
        if (!vulnerData) return;

        // 强制更新数组引用 → Svelte 必刷新
        sortedHashVulns = await sortVulns(
            [...(vulnerData.hasCWEVulns || [])],
            sort_flag,
        );
        sortedEmptyHashVulns = await sortVulns(
            [...(vulnerData.emptyCWEVulns || [])],
            sort_flag,
        );
    }

    // ==============================
    // 颜色使用 final_score（排序后真实分数）
    // ==============================
    function getScoreColor(score: number): string {
        if (score >= 7) return "bg-red-500 text-white";
        if (score >= 3) return "bg-yellow-500 text-white";
        return "bg-green-500 text-white";
    }

    onMount(async () => {
        if ($currentTimestamp === null) {
            console.error("currentTimestamp 错误");
            return;
        }

        currentNumber = $currentTimestamp.number;
        currenttimestamp = $currentTimestamp.timestamp;
        window.location.hash = String(currentNumber);

        const data = await fetchVulnerData(currentNumber);
        vulnerData = data;
        vulnerPage.set(new Map([[currentNumber, vulnerData]]));

        handleSortChange();
    });

    function controlExpand(e: MouseEvent) {
        const btn = e.currentTarget as HTMLElement;
        const parent = btn.closest("[data-expand]") as HTMLElement;
        if (!parent) return;
        const expanded = parent.dataset.expand === "true";
        parent.dataset.expand = expanded ? "false" : "true";
        const content = parent.querySelector(".expand-body") as HTMLElement;
        const arrow = parent.querySelector(".arrow-svg") as HTMLElement;
        if (!content || !arrow) return;

        if (expanded) {
            content.style.height = "0";
            arrow.classList.remove("rotate-180");
        } else {
            content.style.height = content.scrollHeight + "px";
            arrow.classList.add("rotate-180");
        }
    }
</script>

<!-- 下面 HTML 完全不变，只改一处颜色绑定 -->
<!-- 把 getScoreColor(item.score) 改成 getScoreColor(item.final_score) -->

<div
    class="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 p-4 md:p-6"
>
    {#if $currentTimestamp === null}
        <div
            class="max-w-7xl mx-auto p-4 bg-red-50 text-red-600 rounded-xl text-center shadow-sm"
        >
            全局变量 currentTimestamp 错误
        </div>
    {:else if !vulnerData}
        <div class="max-w-7xl mx-auto flex justify-center py-12">
            <div class="animate-pulse flex items-center gap-2 text-slate-600">
                <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle
                        class="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        fill="none"
                        stroke-width="4"
                    ></circle>
                    <path
                        class="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                    ></path>
                </svg>
                数据加载中...
            </div>
        </div>
    {:else}
        <div class="max-w-7xl mx-auto">
            <button
                type="button"
                class="px-3 py-1.5 text-sm bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-md transition-colors"
                on:click={() => ($currentTimestamp = null)}
            >
                ← 返回首页
            </button>

            <div class="mb-4">
                <h1 class="text-2xl md:text-3xl font-bold text-slate-800 mb-3">
                    第 {currentNumber} 次扫描结果
                </h1>
                <div
                    class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
                >
                    <div
                        class="bg-white rounded-xl p-4 shadow-sm border border-slate-200"
                    >
                        <p class="text-sm text-slate-500">扫描时间</p>
                        <p class="text-lg font-semibold text-slate-800">
                            {currenttimestamp}
                        </p>
                    </div>
                    <div
                        class="bg-white rounded-xl p-4 shadow-sm border border-slate-200"
                    >
                        <p class="text-sm text-slate-500">带 Hash 漏洞数</p>
                        <p class="text-lg font-semibold text-blue-600">
                            {vulnerData.hasCWEVulns?.length || 0}
                        </p>
                    </div>
                    <div
                        class="bg-white rounded-xl p-4 shadow-sm border border-slate-200"
                    >
                        <p class="text-sm text-slate-500">无 Hash 漏洞数</p>
                        <p class="text-lg font-semibold text-orange-600">
                            {vulnerData.emptyCWEVulns?.length || 0}
                        </p>
                    </div>
                </div>
            </div>

            <div class="flex items-center justify-between mb-4">
                <div
                    class="inline-flex gap-1 bg-white rounded-lg p-1 shadow-sm border border-slate-200"
                >
                    <button
                        type="button"
                        class:bg-blue-500={activeTab === "hash"}
                        class:text-white={activeTab === "hash"}
                        class="relative z-10 w-36 py-2 text-center font-medium rounded-md transition-colors"
                        on:click={() => (activeTab = "hash")}
                    >
                        有 hash 漏洞
                    </button>
                    <button
                        type="button"
                        class:bg-blue-500={activeTab === "empty"}
                        class:text-white={activeTab === "empty"}
                        class="relative z-10 w-36 py-2 text-center font-medium rounded-md transition-colors"
                        on:click={() => (activeTab = "empty")}
                    >
                        无 hash 漏洞
                    </button>
                </div>

                <select
                    bind:value={sort_flag}
                    on:change={handleSortChange}
                    class="px-3 py-2 border border-slate-300 rounded-md text-sm outline-none bg-white"
                >
                    <option value="0">默认排序</option>
                    <option value="1">关联影响</option>
                </select>
            </div>
        </div>

        <div
            class="bg-white rounded-xl shadow-sm border border-slate-200 overflow-x-auto"
        >
            {#if activeTab === "hash"}
                <div class="p-4 space-y-3">
                    {#each sortedHashVulns as item, index}
                        <div
                            class="bg-white border border-slate-200 rounded-lg overflow-hidden"
                            data-expand="false"
                        >
                            <button
                                type="button"
                                class="w-full flex items-center justify-between px-4 py-3 bg-white hover:bg-slate-50 text-left transition-colors"
                                on:click={controlExpand}
                            >
                                <div class="flex items-center gap-3">
                                    <span>{index + 1}</span>
                                    <span>{item.vulnerabilities.tool}</span>

                                    <!-- 🔥 关键修复：颜色用 final_score -->
                                    <span
                                        class={`px-2 py-1 rounded text-xs font-medium ${getScoreColor(item.final_score)}`}
                                    >
                                        {item.final_score.toFixed(1)}
                                    </span>

                                    <span class="text-sm text-gray-500"
                                        >{item.vulnerabilities.warning_id}</span
                                    >
                                </div>
                                <svg
                                    class="w-5 h-5 text-gray-400 transition-transform duration-200 arrow-svg"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                >
                                    <path
                                        stroke-linecap="round"
                                        stroke-linejoin="round"
                                        stroke-width="2"
                                        d="M19 9l-7 7-7-7"
                                    ></path>
                                </svg>
                            </button>

                            <div
                                class="px-4 py-3 border-t border-gray-100 space-y-3 overflow-hidden h-0 transition-all duration-200 expand-body"
                            >
                                <div class="grid grid-cols-2 gap-3">
                                    <div>
                                        <p class="text-xs text-gray-500">CWE</p>
                                        <p class="text-sm">
                                            {item.vulnerabilities.cwe_id || "—"}
                                        </p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">
                                            严重性等级
                                        </p>
                                        <p class="text-sm">
                                            {item.vulnerabilities
                                                .severity_level}
                                        </p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">
                                            置信度
                                        </p>
                                        <p class="text-sm">
                                            {item.vulnerabilities
                                                .confidence_level}
                                        </p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">
                                            漏洞数量
                                        </p>
                                        <p
                                            class="text-sm font-medium text-blue-600"
                                        >
                                            {item.warningCount}
                                        </p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">
                                            漏洞位置
                                        </p>
                                        <p class="text-sm">
                                            {item.vulnerabilities.line}
                                        </p>
                                    </div>
                                </div>
                                <div>
                                    <p class="text-xs text-gray-500">
                                        文件路径
                                    </p>
                                    <p class="text-sm break-all">
                                        {item.vulnerabilities.file_path}
                                    </p>
                                </div>
                                <div>
                                    <p class="text-xs text-gray-500">
                                        漏洞信息
                                    </p>
                                    <p class="text-sm break-all">
                                        {item.vulnerabilities.short_message}
                                    </p>
                                </div>
                            </div>
                        </div>
                    {/each}
                    {#if sortedHashVulns.length === 0}
                        <div class="py-6 text-center text-gray-500">
                            暂无数据
                        </div>
                    {/if}
                </div>
            {:else}
                <div class="p-4 space-y-3">
                    {#each sortedEmptyHashVulns as item, index}
                        <div
                            class="bg-white border border-slate-200 rounded-lg overflow-hidden"
                            data-expand="false"
                        >
                            <button
                                type="button"
                                class="w-full flex items-center justify-between px-4 py-3 bg-white hover:bg-slate-50 text-left transition-colors"
                                on:click={controlExpand}
                            >
                                <div class="flex items-center gap-3">
                                    <span>{index + 1}</span>
                                    <span>{item.vulnerabilities.tool}</span>
                                    <span class="text-sm text-gray-500"
                                        >{item.vulnerabilities.warning_id}</span
                                    >

                                    <!-- 🔥 关键修复：颜色用 final_score -->
                                    <span
                                        class={`px-2 py-1 rounded text-xs font-medium ${getScoreColor(item.final_score)}`}
                                    >
                                        {item.final_score.toFixed(1)}
                                    </span>
                                </div>
                                <svg
                                    class="w-5 h-5 text-gray-400 transition-transform duration-200 arrow-svg"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                >
                                    <path
                                        stroke-linecap="round"
                                        stroke-linejoin="round"
                                        stroke-width="2"
                                        d="M19 9l-7 7-7-7"
                                    ></path>
                                </svg>
                            </button>

                            <div
                                class="px-4 py-3 border-t border-gray-100 space-y-3 overflow-hidden h-0 transition-all duration-200 expand-body"
                            >
                                <div class="grid grid-cols-2 gap-3">
                                    <div>
                                        <p class="text-xs text-gray-500">
                                            严重性等级
                                        </p>
                                        <p class="text-sm">
                                            {item.vulnerabilities
                                                .severity_level}
                                        </p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">
                                            置信度
                                        </p>
                                        <p class="text-sm">
                                            {item.vulnerabilities
                                                .confidence_level}
                                        </p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">
                                            漏洞数量
                                        </p>
                                        <p
                                            class="text-sm font-medium text-blue-600"
                                        >
                                            {item.warningCount}
                                        </p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">
                                            漏洞位置
                                        </p>
                                        <p class="text-sm">
                                            {item.vulnerabilities.line}
                                        </p>
                                    </div>
                                </div>
                                <div>
                                    <p class="text-xs text-gray-500">
                                        文件路径
                                    </p>
                                    <p class="text-sm break-all">
                                        {item.vulnerabilities.file_path}
                                    </p>
                                </div>
                                <div>
                                    <p class="text-xs text-gray-500">
                                        漏洞信息
                                    </p>
                                    <p class="text-sm break-all">
                                        {item.vulnerabilities.short_message}
                                    </p>
                                </div>
                            </div>
                        </div>
                    {/each}
                    {#if sortedEmptyHashVulns.length === 0}
                        <div class="py-6 text-center text-gray-500">
                            暂无数据
                        </div>
                    {/if}
                </div>
            {/if}
        </div>
    {/if}
</div>
