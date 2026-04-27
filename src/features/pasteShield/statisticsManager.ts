/**
 * PasteShield — Statistics Manager
 * 
 * Provides analytics and statistics from scan history.
 * Tracks trends, generates reports, and powers the statistics dashboard.
 */

import { HistoryManager } from '../../utils/historyManager';

export interface DailyStats {
  date: string;
  scans: number;
  detections: number;
  pasted: number;
  cancelled: number;
  bySeverity: Record<string, number>;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
}

export interface WeeklyTrend {
  weekStart: string;
  totalScans: number;
  totalDetections: number;
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
}

export class StatisticsManager {
  private static instance: StatisticsManager | undefined;
  private historyManager: HistoryManager;

  private constructor(historyManager: HistoryManager) {
    this.historyManager = historyManager;
  }

  public static getInstance(historyManager: HistoryManager): StatisticsManager {
    if (!StatisticsManager.instance) {
      StatisticsManager.instance = new StatisticsManager(historyManager);
    }
    return StatisticsManager.instance;
  }

  /**
   * Get overall statistics summary
   */
  public getSummary(): {
    totalScans: number;
    totalDetections: number;
    threatsBlocked: number;
    pastedCount: number;
    cancelledCount: number;
    ignoredCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    topDetectedTypes: Array<{ type: string; count: number }>;
    topCategories: Array<{ category: string; count: number }>;
    averageDetectionsPerScan: number;
  } {
    const stats = this.historyManager.getStatistics();
    const history = this.historyManager.getHistory();

    const typeCounts: Record<string, number> = {};
    const categoryCounts: Record<string, number> = {};

    for (const entry of history) {
      for (const det of entry.detections) {
        typeCounts[det.type] = (typeCounts[det.type] || 0) + 1;
        if (det.category) {
          categoryCounts[det.category] = (categoryCounts[det.category] || 0) + 1;
        }
      }
    }

    const topTypes = Object.entries(typeCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([type, count]) => ({ type, count }));

    const topCategories = Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([category, count]) => ({ category, count }));

    const avgDetections = stats.totalScans > 0 
      ? (stats.totalDetections / stats.totalScans).toFixed(2) 
      : '0';

    return {
      totalScans: stats.totalScans,
      totalDetections: stats.totalDetections,
      threatsBlocked: stats.cancelledCount,
      pastedCount: stats.pastedCount,
      cancelledCount: stats.cancelledCount,
      ignoredCount: stats.ignoredCount,
      criticalCount: stats.bySeverity['critical'] || 0,
      highCount: stats.bySeverity['high'] || 0,
      mediumCount: stats.bySeverity['medium'] || 0,
      lowCount: stats.bySeverity['low'] || 0,
      topDetectedTypes: topTypes,
      topCategories: topCategories,
      averageDetectionsPerScan: parseFloat(avgDetections),
    };
  }

  /**
   * Get daily statistics for the last N days
   */
  public getDailyStats(days: number = 7): DailyStats[] {
    const history = this.historyManager.getHistory();
    const now = new Date();
    const result: DailyStats[] = [];

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      
      const dayStart = new Date(dateStr).getTime();
      const dayEnd = dayStart + (24 * 60 * 60 * 1000);

      const dayEntries = history.filter(entry => 
        entry.timestamp >= dayStart && entry.timestamp < dayEnd
      );

      const bySeverity: Record<string, number> = {};
      let detections = 0;
      let pasted = 0;
      let cancelled = 0;
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;

      for (const entry of dayEntries) {
        detections += entry.detections.length;
        if (entry.actionTaken === 'pasted') pasted++;
        if (entry.actionTaken === 'cancelled') cancelled++;
        
        for (const det of entry.detections) {
          bySeverity[det.severity] = (bySeverity[det.severity] || 0) + 1;
          if (det.severity === 'critical') criticalCount++;
          else if (det.severity === 'high') highCount++;
          else if (det.severity === 'medium') mediumCount++;
          else if (det.severity === 'low') lowCount++;
        }
      }

      result.push({
        date: dateStr,
        scans: dayEntries.length,
        detections,
        pasted,
        cancelled,
        bySeverity,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
      });
    }

    return result;
  }

  /**
   * Get weekly trend analysis
   */
  public getWeeklyTrend(weeks: number = 4): WeeklyTrend[] {
    const history = this.historyManager.getHistory();
    const now = new Date();
    const result: WeeklyTrend[] = [];

    for (let i = weeks - 1; i >= 0; i--) {
      const weekStart = new Date(now);
      weekStart.setDate(weekStart.getDate() - (i * 7));
      weekStart.setDate(weekStart.getDate() - weekStart.getDay()); // Start from Sunday
      const weekStartStr = weekStart.toISOString().split('T')[0];

      const weekStartMs = weekStart.getTime();
      const weekEndMs = weekStartMs + (7 * 24 * 60 * 60 * 1000);

      const weekEntries = history.filter(entry => 
        entry.timestamp >= weekStartMs && entry.timestamp < weekEndMs
      );

      const totalDetections = weekEntries.reduce((sum, e) => sum + e.detections.length, 0);
      
      // Calculate threat level based on severity distribution
      let criticalCount = 0;
      let highCount = 0;
      for (const entry of weekEntries) {
        for (const det of entry.detections) {
          if (det.severity === 'critical') criticalCount++;
          if (det.severity === 'high') highCount++;
        }
      }

      let threatLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
      if (criticalCount > 0) threatLevel = 'critical';
      else if (highCount > 5) threatLevel = 'high';
      else if (totalDetections > 10) threatLevel = 'medium';

      result.push({
        weekStart: weekStartStr,
        totalScans: weekEntries.length,
        totalDetections,
        threatLevel,
      });
    }

    return result;
  }

  /**
   * Get risk score (0-100) based on recent activity
   */
  public getRiskScore(): number {
    const dailyStats = this.getDailyStats(7);
    let score = 0;

    for (const day of dailyStats) {
      const weight = day.date === dailyStats[dailyStats.length - 1].date ? 3 : 1;
      score += (day.criticalCount || 0) * 10 * weight;
      score += (day.highCount || 0) * 5 * weight;
      score += (day.mediumCount || 0) * 2 * weight;
      score += (day.lowCount || 0) * 1 * weight;
    }

    // Normalize to 0-100
    return Math.min(100, Math.round(score / 10));
  }

  /**
   * Generate a comprehensive report
   */
  public generateReport(): string {
    const summary = this.getSummary();
    const dailyStats = this.getDailyStats(7);
    const riskScore = this.getRiskScore();

    const lines: string[] = [
      '╔══════════════════════════════════════════════════════════╗',
      '║           PasteShield Statistics Report                  ║',
      '╚══════════════════════════════════════════════════════════╝',
      '',
      `Generated: ${new Date().toLocaleString()}`,
      '',
      '┌──────────────────────────────────────────────────────────┐',
      '│                    OVERVIEW                              │',
      '└──────────────────────────────────────────────────────────┘',
      '',
      `Total Scans:          ${summary.totalScans}`,
      `Total Detections:     ${summary.totalDetections}`,
      `Threats Blocked:      ${summary.threatsBlocked}`,
      `Pasted (bypassed):    ${summary.pastedCount}`,
      `Average per Scan:     ${summary.averageDetectionsPerScan.toFixed(2)}`,
      '',
      '┌──────────────────────────────────────────────────────────┐',
      '│                 SEVERITY BREAKDOWN                       │',
      '└──────────────────────────────────────────────────────────┘',
      '',
      `Critical:  ${summary.criticalCount}`,
      `High:      ${summary.highCount}`,
      `Medium:    ${summary.mediumCount}`,
      `Low:       ${summary.lowCount}`,
      '',
      `Current Risk Score: ${riskScore}/100`,
      '',
      '┌──────────────────────────────────────────────────────────┐',
      '│              TOP DETECTED TYPES                          │',
      '└──────────────────────────────────────────────────────────┘',
      '',
    ];

    for (const item of summary.topDetectedTypes.slice(0, 5)) {
      lines.push(`  ${item.count.toString().padStart(4)} × ${item.type}`);
    }

    lines.push('');
    lines.push('┌──────────────────────────────────────────────────────────┐');
    lines.push('│              TOP CATEGORIES                              │');
    lines.push('└──────────────────────────────────────────────────────────┘');
    lines.push('');

    for (const item of summary.topCategories.slice(0, 5)) {
      lines.push(`  ${item.count.toString().padStart(4)} × ${item.category}`);
    }

    lines.push('');
    lines.push('┌──────────────────────────────────────────────────────────┐');
    lines.push('│                7-DAY TREND                               │');
    lines.push('└──────────────────────────────────────────────────────────┘');
    lines.push('');

    for (const day of dailyStats) {
      const bar = '█'.repeat(Math.min(20, day.detections));
      lines.push(`${day.date}: ${bar} (${day.detections})`);
    }

    return lines.join('\n');
  }
}
