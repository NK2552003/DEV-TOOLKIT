/**
 * index.ts — Public entry point for the enhanced Freshness Heatmap feature.
 *
 * Drop-in registration in extension.ts:
 *
 *   import { registerFreshnessHeatmap } from "./features/freshnessHeatmap";
 *   export function activate(context: vscode.ExtensionContext) {
 *     registerFreshnessHeatmap(context);
 *   }
 */

import * as vscode from "vscode";
import { FreshnessHeatmapController } from "./freshnessHeatmapController";
import { FreshnessDashboardViewProvider } from "./dashboardView";

export function registerFreshnessHeatmap(
  context: vscode.ExtensionContext
): vscode.Disposable {
  const dashboardView = new FreshnessDashboardViewProvider(context);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(
      "devToolkit.freshnessDashboard",
      dashboardView,
      { webviewOptions: { retainContextWhenHidden: true } }
    )
  );

  const ctrl = new FreshnessHeatmapController(context, dashboardView);

  const cmds = [
    vscode.commands.registerCommand(
      "devToolkit.toggleFreshnessHeatmap",
      () => ctrl.toggle()
    ),
    vscode.commands.registerCommand(
      "devToolkit.refreshFreshnessHeatmap",
      () => ctrl.refresh()
    ),
    vscode.commands.registerCommand(
      "devToolkit.cycleHeatmapMode",
      () => ctrl.cycleMode()
    ),
    vscode.commands.registerCommand(
      "devToolkit.openFreshnessDashboard",
      () => ctrl.openDashboard()
    ),
  ];

  context.subscriptions.push(...cmds, ctrl);

  return { dispose() { for (const c of cmds) { c.dispose(); } ctrl.dispose(); } };
}

export { FreshnessHeatmapController } from "./freshnessHeatmapController";
export * from "./types";
