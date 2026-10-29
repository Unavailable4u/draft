import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "computer-modern/cmu-serif.css";
import "computer-modern/cmu-typewriter-text.css";
import App from "./App";
import "./index.css";

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
