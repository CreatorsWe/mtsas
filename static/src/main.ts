import { mount } from "svelte";
import "./app.css";
import App from "./App.svelte";

import "virtual:uno.css"; // 👈 必须加

const app = mount(App, {
    target: document.getElementById("app")!,
});

export default app;
