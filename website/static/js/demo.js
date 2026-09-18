/** Static deterministic demo — no fetch, no live scan.
 * @typedef {{id:string,title:string,severity:string,status:string,surface:string}} DemoFinding
 */
export function initDemo() {
  const data = window.DEMO_ASSESSMENT;
  if (!data) return;
  setDemoState("verified");
}
export function setDemoState(s) {
  const c = document.getElementById("demo-console");
  if (c) c.dataset.state = s;
}
document.addEventListener("DOMContentLoaded", initDemo);
