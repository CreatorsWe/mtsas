import { defineConfig } from "unocss";
import presetUno from "@unocss/preset-uno";
import presetwind3 from "@unocss/preset-wind3";

export default defineConfig({
    presets: [
        presetwind3(), // 启用默认原子化规则
    ],
    // 👇 让 UnoCSS 扫描所有 .svelte 文件里的原子类
    content: {
        pipeline: {
            include: [/\.(svelte|html|js|ts)$/],
        },
    },
});
