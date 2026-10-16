// client compliance report: the Print / Save as PDF button (inline handlers aren't allowed by the security policy)
document.getElementById("printBtn")?.addEventListener("click", () => window.print());
