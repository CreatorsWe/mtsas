<script lang="ts">
    import { onMount } from "svelte";
    import { type IndexData, fetchIndexData } from "./utils/indexFetch";
    import { currentTimestamp } from "../store";

    let indexdata: Promise<IndexData>;

    onMount(() => {
        window.history.replaceState(null, "", window.location.pathname);
        indexdata = fetchIndexData();
    });
</script>

<div class="min-h-screen bg-slate-50 p-8">
    <div class="max-w-4xl mx-auto">
        {#await indexdata}
            <div class="text-center py-14">
                <div class="inline-block animate-pulse text-lg text-slate-600">加载中...</div>
            </div>
        {:then data}
            {#if !data}
                <div class="p-4 bg-red-50 text-red-600 rounded-lg text-center">数据为空</div>
            {:else}
                <h1 class="text-3xl font-bold text-center text-slate-800 mb-8">
                    {data.projectName} 扫描结果
                </h1>

                <div class="bg-white rounded-xl p-6 shadow-sm border border-slate-100 space-y-3">
                    {#each data.timestampMaps || [] as item (item.number)}
                        <button
                            type="button"
                            class="w-full p-6 rounded-xl bg-slate-50 border border-slate-200 text-lg font-medium transition-all duration-300 text-left hover:bg-blue-50 hover:border-blue-300 hover:shadow-lg active:scale-[0.97] cursor-pointer"
                            on:click={() => ($currentTimestamp = item)}
                        >
                            <span class="text-blue-700 font-semibold">NO.{item.number}</span>
                            <span class="ml-3 text-slate-700">{item.timestamp}</span>
                        </button>
                    {/each}
                </div>
            {/if}
        {:catch error}
            <div class="p-4 bg-red-50 text-red-600 rounded-lg text-center">
                数据加载失败：{(error as Error)?.message || "未知错误"}
            </div>
        {/await}
    </div>
</div>
