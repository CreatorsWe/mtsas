<script lang="ts">
    import { currentTimestamp } from "../store";
    import { onMount } from "svelte";
    import { type VulnerData, type ScopeRange } from "./utils/types";
    import { fetchVulnerData } from "./utils/vulnerFetch";
    import Code from "./code.svelte";

    let vulnerData: Promise<VulnerData>;
    let currentNumber: number;
    let currenttimestamp: string;

    // 🔥 修复：统一命名为 empty
    let activeTab = "hash"; // hash / empty

    onMount(() => {
        // 🔥 修复1：为空直接 return，不发错误请求
        if ($currentTimestamp === null) {
            console.error("currentTimestamp 错误");
            return;
        }

        currentNumber = $currentTimestamp.number;
        currenttimestamp = $currentTimestamp.timestamp;
        window.location.hash = String(currentNumber);

        // 🔥 修复2：只在合法时获取数据
        vulnerData = fetchVulnerData(currentNumber);
    });

    // svg 调用函数，获取 爷爷 DOM 节点的 data-expand 值
    function controlExpand(e: MouseEvent) {
        // 获取当前点击的元素
        const current = e.target as HTMLElement;
        // 1.获取父节点的data-expand 属性
        const parentDiv = current?.parentElement;
        if (parentDiv === null) {
            console.warn("该 button 节点的父节点为 null");
            return;
        }
        let dataExpand = parentDiv.dataset?.expand;
        if (dataExpand === undefined) {
            console.warn("button 节点的父节点不存在 data-expand 属性");
            return;
        }

        // 2. 改变 data-expand 属性，改变 svg 和 button 的直接兄弟的样式
        parentDiv.dataset.expand = dataExpand === "false" ? "true" : "false";
        let newDataExpand = parentDiv.dataset.expand;

        // 获取 svg
        const svgChild = current.querySelector("svg") as HTMLElement | null;
        if (svgChild === null) {
            console.warn("该 button 节点的子节点 svg 为 null");
            return;
        }

        // 获取直接兄弟节点
        const expandDiv = current.nextElementSibling as HTMLElement | null;
        if (expandDiv === null) {
            console.warn("该 button 节点的直接兄弟节点为 null");
            return;
        }

        if (newDataExpand === "false") {
            // 收起：高度 → 0
            expandDiv.style.height = "0";
            svgChild.classList.remove("rotate-180");
        } else {
            // 展开：高度 → 滚动高度（真实高度）
            expandDiv.style.height = expandDiv.scrollHeight + "px";
            svgChild.classList.add("rotate-180");
        }
    }

    // 计算在指定区间内以指定数为中心，选取指定范围的区别，左右最平均的区间
    function averageRange(total_range: ScopeRange, number: number, range: number): ScopeRange {
        // 基础左右平分（最平均）
        const left = Math.floor(range / 2);
        const right = range - left;

        // 0 索引下最大可扩展空间
        const maxLeft = number - total_range.start;
        const maxRight = total_range.end - number;

        // 先按对称取，不越界
        let realLeft = Math.min(left, maxLeft);
        let realRight = Math.min(right, maxRight);

        // 补剩余数量（保持最平均）
        const remain = range - realLeft - realRight;
        if (remain > 0) {
            const addRight = Math.min(remain, maxRight - realRight);
            realRight += addRight;
            realLeft += remain - addRight;
        }

        return {
            start: number - realLeft,
            end: number + realRight,
        };
    }
</script>

<div class="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 p-4 md:p-8">
    {#if $currentTimestamp === null}
        <div class="max-w-7xl mx-auto p-4 bg-red-50 text-red-600 rounded-xl text-center shadow-sm">全局变量 currentTimestamp 错误</div>
    {:else}
        {#await vulnerData}
            <div class="max-w-7xl mx-auto flex justify-center py-20">
                <div class="animate-pulse flex items-center gap-2 text-slate-600">
                    <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" fill="none" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                    </svg>
                    数据加载中...
                </div>
            </div>
        {:then data}
            {#if !data}
                <div class="p-4 bg-red-50 text-red-600 rounded-lg text-center">数据为空</div>
            {:else}
                <div class="max-w-7xl mx-auto">
                    <button class="" on:click={() => ($currentTimestamp = null)}>返回首页</button>
                    <div class="mb-8">
                        <h1 class="text-2xl md:text-3xl font-bold text-slate-800 mb-4">
                            第 {currentNumber} 次扫描结果
                        </h1>
                        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                            <div class="bg-white rounded-xl p-4 shadow-sm border border-slate-200">
                                <p class="text-sm text-slate-500">扫描时间</p>
                                <p class="text-lg font-semibold text-slate-800">
                                    {currenttimestamp}
                                </p>
                            </div>
                            <div class="bg-white rounded-xl p-4 shadow-sm border border-slate-200">
                                <p class="text-sm text-slate-500">带 Hash 漏洞数</p>
                                <p class="text-lg font-semibold text-blue-600">
                                    {data.hashVulns?.length || 0}
                                </p>
                            </div>
                            <div class="bg-white rounded-xl p-4 shadow-sm border border-slate-200">
                                <p class="text-sm text-slate-500">无 Hash 漏洞数</p>
                                <p class="text-lg font-semibold text-orange-600">
                                    {data.emptyHashVulns?.length || 0}
                                </p>
                            </div>
                        </div>
                    </div>

                    <div class="relative mb-6 bg-white rounded-lg p-1 inline-flex shadow-sm border border-slate-200">
                        <div class="absolute inset-y-1 w-1/2 bg-blue-500 rounded-md transition-all duration-300 shadow-sm z-0 {activeTab === 'hash' ? 'left-0' : 'left-1/2'}"></div>
                        <button
                            class="relative z-10 w-40 py-2 text-center font-medium transition-colors duration-300 text-white={activeTab === 'hash'}"
                            class:text-slate-700={activeTab !== "hash"}
                            on:click={() => (activeTab = "hash")}
                        >
                            有 hash 漏洞
                        </button>

                        <button
                            class="relative z-10 w-40 py-2 text-center font-medium transition-colors duration-300 text-white={activeTab === 'empty'}"
                            class:text-slate-700={activeTab !== "empty"}
                            on:click={() => (activeTab = "empty")}
                        >
                            无 hash 漏洞
                        </button>
                    </div>
                </div>

                <div class="bg-white rounded-xl shadow-sm border border-slate-200 overflow-x-auto">
                    {#if activeTab === "hash"}
                        <div class="p-4 space-y-3">
                            {#each data?.hashVulns || [] as item, index}
                                <div class="bg-white border border-slate-200 rounded-lg overflow-hidden" data-expand="false">
                                    <!-- 卡片头部：点击切换 -->
                                    <button
                                        type="button"
                                        class="w-full flex items-center justify-between px-4 py-3 cursor-pointer bg-white hover:bg-slate-50 border-none text-left"
                                        on:click={controlExpand}
                                    >
                                        <div class="flex items-center gap-3">
                                            <span>{index + 1}</span>
                                            <span>{item.vulnerabilities.tool}</span>
                                            <span class="text-sm text-gray-500">
                                                {item.vulnerabilities.warning_id}
                                            </span>
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

                                        <svg class="w-5 h-5 text-gray-400 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                                        </svg>
                                    </button>

                                    <!-- 展开内容：仅当 id 在集合中时显示 -->
                                    <div
                                        class="px-4 py-3 border-t border-gray-100 space-y-2
                                             overflow-hidden h-0
                                             transition-all duration-200 ease-out"
                                    >
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
                                                <p class="text-xs text-gray-500">ScopeOffsetID</p>
                                                <p class="text-sm">{item.scopeoffsetID}</p>
                                            </div>
                                            <div>
                                                <p class="text-xs text-gray-500">文件路径</p>
                                                <p class="text-sm">{item.vulnerabilities.file_path}</p>
                                            </div>
                                            <div>
                                                <p class="text-xs text-gray-500">漏洞信息</p>
                                                <p class="text-sm">{item.vulnerabilities.short_messgae}</p>
                                            </div>
                                        </div>
                                        <div>
                                            <Code
                                                filepath={item.vulnerabilities.file_path}
                                                range={averageRange(item.optimalscope, item.vulnerabilities.range.start_line, 10)}
                                                bugpos={item.vulnerabilities.range.start_line}
                                            />
                                        </div>
                                    </div>
                                </div>
                            {/each}

                            {#if !data?.hashVulns?.length}
                                <div class="py-8 text-center text-gray-500">暂无数据</div>
                            {/if}
                        </div>
                    {:else}
                        <!-- emptyhash 逻辑完全一样，复用同一套状态与函数 -->
                        <!-- <div class="p-4 space-y-3">
                        {#each (data?.emptyhashvulns || []) as item}
                          {#key item.vulnerabilities.warning_id}
                            <div class="bg-white border border-slate-200 rounded-lg overflow-hidden">
                              <div
                                class="flex items-center justify-between px-4 py-3 cursor-pointer hover:bg-slate-50"
                                on:click={() => toggleExpand(item.vulnerabilities.warning_id)}
                              >
                                <div class="flex items-center gap-3">
                                  <span class="text-sm text-gray-500">
                                    {item.vulnerabilities.warning_id}
                                  </span>
                                  <span class="px-2 py-1 rounded text-xs font-medium
                                    {item.vulnerabilities.severity_level === 'LOW' ? 'bg-green-100 text-green-700' :
                                     item.vulnerabilities.severity_level === 'MEDIUM' ? 'bg-yellow-100 text-yellow-700' :
                                     item.vulnerabilities.severity_level === 'HIGH' ? 'bg-orange-100 text-orange-700' :
                                     item.vulnerabilities.severity_level === 'CRITICAL' ? 'bg-red-100 text-red-700' :
                                     'bg-gray-100 text-gray-700'}">
                                    {item.vulnerabilities.severity_level}
                                  </span>
                                </div>

                                <svg class="w-5 h-5 text-gray-400 transition-transform {expandedIds.has(item.vulnerabilities.warning_id) ? 'rotate-180' : ''}"
                                     fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                                </svg>
                              </div>

                              {#if expandedIds.has(item.vulnerabilities.warning_id)}
                                <div class="px-4 py-3 border-t border-gray-100 space-y-2">
                                  <div class="grid grid-cols-2 gap-3">
                                    <div>
                                      <p class="text-xs text-gray-500">扫描工具</p>
                                      <p class="text-sm">{item.vulnerabilities.tool}</p>
                                    </div>
                                    <div>
                                      <p class="text-xs text-gray-500">置信度</p>
                                      <p class="text-sm">{item.vulnerabilities.confidence_level}</p>
                                    </div>
                                  </div>
                                </div>
                              {/if}
                            </div>
                          {/key}
                        {/each}

                        {#if !data?.emptyhashvulns?.length}
                          <div class="py-8 text-center text-gray-500">暂无数据</div>
                        {/if}
                      </div> -->
                    {/if}
                </div>
            {/if}
        {:catch error}
            <div class="p-4 bg-red-50 text-red-600 rounded-lg text-center">
                数据加载失败：{(error as Error)?.message || "未知错误"}
            </div>
        {/await}
    {/if}
</div>
