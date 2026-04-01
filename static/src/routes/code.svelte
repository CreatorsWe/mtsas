<script lang="ts">
    import { type ScopeRange, type Range } from "./utils/types";

    // export interface Range {
    //     start_line: number;
    //     end_line: number | null;
    //     start_column: number;
    //     end_column: number | null;
    // }

    // export interface ScopeRange {
    //     start: number;
    //     end: number;
    // }
    interface CodeRequest {
        file_path: string;
        read_scope: ScopeRange;
        bug_pos: Range;
    }

    export interface CodeInfo {
        number: number;
        content: string;
        isbug: boolean;
    }

    // Props
    const { filepath, range, bugpos } = $props<{
        filepath: string;
        range: ScopeRange;
        bugpos: number;
    }>();

    let codeLines = $state<CodeInfo[]>([]);
    let isLoading = $state(true);
    let error = $state<string | null>(null);

    $effect(() => {
        const fetchCode = async () => {
            console.log("请求参数:", { filepath, range, bugpos });

            if (!filepath) {
                error = "文件路径不能为空";
                isLoading = false;
                return;
            }

            try {
                isLoading = true;
                error = null;

                const reqBody: CodeRequest = {
                    file_path: filepath,
                    read_scope: range,
                    bug_pos: bugpos,
                };

                const res = await fetch("http://localhost:8080/mtsas/code", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(reqBody),
                });

                if (!res.ok) throw new Error(`HTTP 错误 ${res.status}`);

                // ✅ 安全获取数据（修复核心）
                const raw = await res.json();
                console.log("后端原始返回:", raw);

                // ✅ 确保一定是数组
                const data: CodeInfo[] = Array.isArray(raw) ? raw : raw?.data || [];

                if (data.length === 0) {
                    error = "未获取到代码内容";
                    isLoading = false;
                    return;
                }

                codeLines = data;
            } catch (err) {
                console.error("加载失败:", err);
                error = (err as Error).message || "加载代码失败";
            } finally {
                isLoading = false;
            }
        };

        fetchCode();
    });
</script>

<!-- 纯白背景 + 蓝色代码 + 红色波浪线 + 行号对齐 -->
<div class="max-w-5xl mx-auto my-4 bg-white border border-gray-200 shadow-sm rounded">
    {#if isLoading}
        <div class="p-8 text-center text-gray-500">
            <div class="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin inline-block"></div>
            <p class="mt-2">加载中...</p>
        </div>
    {:else if error}
        <div class="p-6 text-red-500 text-center">⚠️ {error}</div>
    {:else}
        <div class="p-4 bg-gray-100 border border-gray-300 rounded font-mono text-sm">
            {#each codeLines as line}
                <div class="flex items-center h-[1.25rem] leading-none">
                    <span class="w-[36px] text-right text-gray-500 pr-1 select-none">
                        {line.number}
                    </span>
                    <pre
                        class="m-0 text-blue-700 whitespace-pre flex-1
        {line.isbug ? 'text-red-500' : ''}">
        {line.content}
      </pre>
                </div>
            {/each}
        </div>
    {/if}
</div>
