<script lang="ts">
    import { currentTimestamp } from "./store";
    import Vulner from "./routes/vulner.svelte";
    import Index from "./routes/index.svelte";
    import { onMount } from "svelte";

    $: currentComp = $currentTimestamp === null ? Index : Vulner;

    onMount(() => {});
</script>

<svelte:component this={currentComp} />
