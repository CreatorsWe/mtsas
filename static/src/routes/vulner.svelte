<script lang="ts">
    import { currentTimestamp } from "../store";
    import { onMount } from "svelte";
    import { type VulnerData, type DbVulnerability, type SeverityLevel, type ConfidenceLevel } from "./utils/types";
    import { fetchVulnerData } from "./utils/vulnerFetch";
    let vulnerData: VulnerData | null = null;
    let currentNumber: number;
    let currenttimestamp: string;
    let activeTab = "hash";
    // 排序
    let sortBy = "severity";
    let sortedHashVulns: DbVulnerability[] = [];
    let sortedEmptyHashVulns: DbVulnerability[] = [];
    // CWE 弹窗
    let showCweModal = false;
    let currentEditItem: DbVulnerability | null = null;
    let cweInputValue = "";
    const severityWeight: Record<SeverityLevel, number> = {
        UNKNOWN: 0,
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4,
    };
    const confidenceWeight: Record<ConfidenceLevel, number> = {
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
    };
    function sortVulns(list: DbVulnerability[]): DbVulnerability[] {
        if (!list || list.length === 0) return [];
        return [...list].sort((a, b) => {
            const vulnA = a.vulnerabilities;
            const vulnB = b.vulnerabilities;
            if (sortBy === "severity") {
                const sA = severityWeight[vulnA.severity_level] || 0;
                const sB = severityWeight[vulnB.severity_level] || 0;
                if (sA !== sB) return sB - sA;
                const cA = confidenceWeight[vulnA.confidence_level] || 0;
                const cB = confidenceWeight[vulnB.confidence_level] || 0;
                return cB - cA;
            } else {
                const countA = a.warningCount || 0;
                const countB = b.warningCount || 0;
                if (countA !== countB) return countB - countA;
                const cA = confidenceWeight[vulnA.confidence_level] || 0;
                const cB = confidenceWeight[vulnB.confidence_level] || 0;
                return cB - cA;
            }
        });
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
    });
    $: {
        if (vulnerData) {
            sortedHashVulns = sortVulns(vulnerData.hashVulns || []);
            sortedEmptyHashVulns = sortVulns(vulnerData.emptyHashVulns || []);
        }
    }
    // 展开收起（修复版，无嵌套、无警告）
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

<div class="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 p-4 md:p-6">
    {#if $currentTimestamp === null}
        <div class="max-w-7xl mx-auto p-4 bg-red-50 text-red-600 rounded-xl text-center shadow-sm">全局变量 currentTimestamp 错误</div>
    {:else if !vulnerData}
        <div class="max-w-7xl mx-auto flex justify-center py-12">
            <div class="animate-pulse flex items-center gap-2 text-slate-600">
                <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" fill="none" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                </svg>
                数据加载中...
            </div>
        </div>
    {:else}
        <div class="max-w-7xl mx-auto">
            <!-- 1. 优化返回首页按钮 -->
            <button type="button" class="px-3 py-1.5 text-sm bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-md transition-colors" on:click={() => ($currentTimestamp = null)}>
                ← 返回首页
            </button>

            <!-- 2. 减小 mb-8 → mb-4，降低整体高度 -->
            <div class="mb-4">
                <h1 class="text-2xl md:text-3xl font-bold text-slate-800 mb-3">第 {currentNumber} 次扫描结果</h1>
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div class="bg-white rounded-xl p-4 shadow-sm border border-slate-200">
                        <p class="text-sm text-slate-500">扫描时间</p>
                        <p class="text-lg font-semibold text-slate-800">{currenttimestamp}</p>
                    </div>
                    <div class="bg-white rounded-xl p-4 shadow-sm border border-slate-200">
                        <p class="text-sm text-slate-500">带 Hash 漏洞数</p>
                        <p class="text-lg font-semibold text-blue-600">{vulnerData.hashVulns?.length || 0}</p>
                    </div>
                    <div class="bg-white rounded-xl p-4 shadow-sm border border-slate-200">
                        <p class="text-sm text-slate-500">无 Hash 漏洞数</p>
                        <p class="text-lg font-semibold text-orange-600">{vulnerData.emptyHashVulns?.length || 0}</p>
                    </div>
                </div>
            </div>

            <!-- 3. 优化切换动画 + 4. select 排序靠右 -->
            <div class="flex items-center justify-between mb-4">
                <!-- 左侧：无滑块，点击按钮直接变色 -->
                <div class="inline-flex gap-1 bg-white rounded-lg p-1 shadow-sm border border-slate-200">
                    <button
                        type="button"
                        class="relative z-10 w-36 py-2 text-center font-medium rounded-md transition-colors"
                        class:bg-blue-500={activeTab === "hash"}
                        class:text-white={activeTab === "hash"}
                        class:bg-transparent={activeTab !== "hash"}
                        class:text-slate-700={activeTab !== "hash"}
                        on:click={() => (activeTab = "hash")}
                    >
                        有 hash 漏洞
                    </button>

                    <button
                        type="button"
                        class="relative z-10 w-36 py-2 text-center font-medium rounded-md transition-colors"
                        class:bg-blue-500={activeTab === "empty"}
                        class:text-white={activeTab === "empty"}
                        class:bg-transparent={activeTab !== "empty"}
                        class:text-slate-700={activeTab !== "empty"}
                        on:click={() => (activeTab = "empty")}
                    >
                        无 hash 漏洞
                    </button>
                </div>

                <!-- 右侧排序 -->
                <select bind:value={sortBy} class="px-3 py-2 border border-slate-300 rounded-md text-sm outline-none bg-white">
                    <option value="severity">按严重性等级</option>
                    <option value="count">按警告数量</option>
                </select>
            </div>
        </div>

        <div class="bg-white rounded-xl shadow-sm border border-slate-200 overflow-x-auto">
            {#if activeTab === "hash"}
                <div class="p-4 space-y-3">
                    {#each sortedHashVulns as item, index}
                        <div class="bg-white border border-slate-200 rounded-lg overflow-hidden" data-expand="false">
                            <button type="button" class="w-full flex items-center justify-between px-4 py-3 bg-white hover:bg-slate-50 text-left transition-colors" on:click={controlExpand}>
                                <div class="flex items-center gap-3">
                                    <span>{index + 1}</span>
                                    <span>{item.vulnerabilities.tool}</span>
                                    <span class="text-sm text-gray-500">{item.vulnerabilities.warning_id}</span>
                                    <span
                                        class="px-2 py-1 rounded text-xs font-medium
                                        {item.vulnerabilities.severity_level === 'LOW'
                                            ? 'bg-green-100 text-green-700'
                                            : item.vulnerabilities.severity_level === 'MEDIUM'
                                              ? 'bg-yellow-100 text-yellow-700'
                                              : item.vulnerabilities.severity_level === 'HIGH'
                                                ? 'bg-orange-100 text-orange-700'
                                                : item.vulnerabilities.severity_level === 'CRITICAL'
                                                  ? 'bg-red-100 text-red-700'
                                                  : 'bg-gray-100 text-gray-700'}"
                                    >
                                        {item.vulnerabilities.severity_level}
                                    </span>
                                </div>
                                <svg class="w-5 h-5 text-gray-400 transition-transform duration-200 arrow-svg" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                                </svg>
                            </button>
                            <!-- 5. 优化展开布局：文件路径 & 漏洞信息各占一行 -->
                            <div class="px-4 py-3 border-t border-gray-100 space-y-3 overflow-hidden h-0 transition-all duration-200 expand-body">
                                <div class="grid grid-cols-2 gap-3">
                                    <div>
                                        <p class="text-xs text-gray-500">扫描工具</p>
                                        <p class="text-sm">{item.vulnerabilities.tool}</p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">警告编号</p>
                                        <p class="text-sm">{item.vulnerabilities.warning_id}</p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">CWE</p>
                                        <p class="text-sm">{item.vulnerabilities.cwe_id || "—"}</p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">置信度</p>
                                        <p class="text-sm">{item.vulnerabilities.confidence_level}</p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">漏洞数量</p>
                                        <p class="text-sm font-medium text-blue-600">{item.warningCount}</p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">漏洞位置</p>
                                        <p class="text-sm">{item.vulnerabilities.range.start_line}</p>
                                    </div>
                                </div>
                                <!-- 文件路径 独占一行 -->
                                <div>
                                    <p class="text-xs text-gray-500">文件路径</p>
                                    <p class="text-sm break-all">{item.vulnerabilities.file_path}</p>
                                </div>
                                <!-- 漏洞信息 独占一行 -->
                                <div>
                                    <p class="text-xs text-gray-500">漏洞信息</p>
                                    <p class="text-sm break-all">{item.vulnerabilities.short_messgae}</p>
                                </div>
                            </div>
                        </div>
                    {/each}
                    {#if sortedHashVulns.length === 0}
                        <div class="py-6 text-center text-gray-500">暂无数据</div>
                    {/if}
                </div>
            {:else}
                <div class="p-4 space-y-3">
                    {#each sortedEmptyHashVulns as item, index}
                        <div class="bg-white border border-slate-200 rounded-lg overflow-hidden" data-expand="false">
                            <button type="button" class="w-full flex items-center justify-between px-4 py-3 bg-white hover:bg-slate-50 text-left transition-colors" on:click={controlExpand}>
                                <div class="flex items-center gap-3">
                                    <span>{index + 1}</span>
                                    <span>{item.vulnerabilities.tool}</span>
                                    <span class="text-sm text-gray-500">{item.vulnerabilities.warning_id}</span>
                                    <span
                                        class="px-2 py-1 rounded text-xs font-medium
                                        {item.vulnerabilities.severity_level === 'LOW'
                                            ? 'bg-green-100 text-green-700'
                                            : item.vulnerabilities.severity_level === 'MEDIUM'
                                              ? 'bg-yellow-100 text-yellow-700'
                                              : item.vulnerabilities.severity_level === 'HIGH'
                                                ? 'bg-orange-100 text-orange-700'
                                                : item.vulnerabilities.severity_level === 'CRITICAL'
                                                  ? 'bg-red-100 text-red-700'
                                                  : 'bg-gray-100 text-gray-700'}"
                                    >
                                        {item.vulnerabilities.severity_level}
                                    </span>
                                </div>
                                <svg class="w-5 h-5 text-gray-400 transition-transform duration-200 arrow-svg" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                                </svg>
                            </button>
                            <!-- 5. 无hash也统一优化 -->
                            <div class="px-4 py-3 border-t border-gray-100 space-y-3 overflow-hidden h-0 transition-all duration-200 expand-body">
                                <div class="grid grid-cols-2 gap-3">
                                    <div>
                                        <p class="text-xs text-gray-500">扫描工具</p>
                                        <p class="text-sm">{item.vulnerabilities.tool}</p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">警告编号</p>
                                        <p class="text-sm">{item.vulnerabilities.warning_id}</p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">置信度</p>
                                        <p class="text-sm">{item.vulnerabilities.confidence_level}</p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">漏洞数量</p>
                                        <p class="text-sm font-medium text-blue-600">{item.warningCount}</p>
                                    </div>
                                    <div>
                                        <p class="text-xs text-gray-500">漏洞位置</p>
                                        <p class="text-sm">{item.vulnerabilities.range.start_line}</p>
                                    </div>
                                </div>
                                <div>
                                    <p class="text-xs text-gray-500">文件路径</p>
                                    <p class="text-sm break-all">{item.vulnerabilities.file_path}</p>
                                </div>
                                <div>
                                    <p class="text-xs text-gray-500">漏洞信息</p>
                                    <p class="text-sm break-all">{item.vulnerabilities.short_messgae}</p>
                                </div>
                            </div>
                        </div>
                    {/each}
                    {#if sortedEmptyHashVulns.length === 0}
                        <div class="py-6 text-center text-gray-500">暂无数据</div>
                    {/if}
                </div>
            {/if}
        </div>
    {/if}
</div>
