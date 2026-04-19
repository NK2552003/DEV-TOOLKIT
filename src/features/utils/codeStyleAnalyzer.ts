import * as vscode from "vscode";

export interface CodeStyleMood {
  mood: "God-level" | "Clean" | "Neat" | "Messy";
  emoji: string;
  score: number;
  details: {
    lineLength: string;
    naming: string;
    comments: string;
    functions: string;
    complexity: string;
  };
  tooltip: string;
}

const HEURISTICS = {
  IDEAL_LINE_LENGTH: 80,
  MAX_LINE_LENGTH: 120,
  IDEAL_FUNCTION_LENGTH: 20,
  MAX_FUNCTION_LENGTH: 50,
  COMMENT_RATIO_GOOD: 0.2,
  COMMENT_RATIO_IDEAL: 0.15,
};

export function analyzeCodeStyle(document: vscode.TextDocument): CodeStyleMood {
  const text = document.getText();
  const lines = text.split("\n");

  const metrics = {
    avgLineLength: 0,
    longLineCount: 0,
    veryLongLineCount: 0,
    commentLineCount: 0,
    codeLineCount: 0,
    totalLines: 0,
    functionCount: 0,
    avgFunctionLength: 0,
    consoleLogCount: 0,
    todoCount: 0,
    variableNamingScore: 0,
    complexityScore: 0,
  };

  // Analyze lines
  let totalLineLength = 0;
  let functionLengths: number[] = [];
  let currentFunctionLength = 0;
  let inFunction = false;

  lines.forEach((line) => {
    const trimmed = line.trim();
    metrics.totalLines++;

    if (trimmed.length === 0) return;

    // Line length analysis
    totalLineLength += line.length;
    if (line.length > HEURISTICS.MAX_LINE_LENGTH) {
      metrics.veryLongLineCount++;
    } else if (line.length > HEURISTICS.IDEAL_LINE_LENGTH) {
      metrics.longLineCount++;
    }

    // Comment analysis
    if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
      metrics.commentLineCount++;
    } else {
      metrics.codeLineCount++;
    }

    // Console log & TODO detection
    if (trimmed.includes("console.")) {
      metrics.consoleLogCount++;
    }
    if (trimmed.includes("TODO") || trimmed.includes("FIXME")) {
      metrics.todoCount++;
    }

    // Function detection
    if (trimmed.includes("function") || trimmed.includes("=>") || trimmed.includes("async")) {
      if (!inFunction) {
        inFunction = true;
        metrics.functionCount++;
        currentFunctionLength = 0;
      }
    }

    if (inFunction) {
      currentFunctionLength++;
      if (trimmed === "}" || trimmed.endsWith("}")) {
        functionLengths.push(currentFunctionLength);
        inFunction = false;
      }
    }
  });

  metrics.avgLineLength = totalLineLength / metrics.codeLineCount || 0;
  metrics.avgFunctionLength =
    functionLengths.length > 0 ? functionLengths.reduce((a, b) => a + b, 0) / functionLengths.length : 0;

  // Analyze naming conventions
  metrics.variableNamingScore = analyzeNaming(text);

  // Calculate scores
  const lineScore = calculateLineScore(metrics);
  const commentScore = calculateCommentScore(metrics);
  const functionScore = calculateFunctionScore(metrics);
  const cleanlinessScore = calculateCleanliness(metrics);

  const overallScore = (lineScore + commentScore + functionScore + cleanlinessScore) / 4;

  // Determine mood
  const mood = determineMood(overallScore);
  const emoji = getMoodEmoji(mood.level);

  const details = {
    lineLength: formatLineMetric(metrics),
    naming: `Naming Quality: ${(metrics.variableNamingScore * 100).toFixed(0)}%`,
    comments: `Comment Ratio: ${((metrics.commentLineCount / metrics.totalLines) * 100).toFixed(1)}%`,
    functions: `Avg Function Length: ${metrics.avgFunctionLength.toFixed(0)} lines`,
    complexity: `Cleanliness: ${formatCleanliness(metrics)}`,
  };

  const tooltip = buildTooltip(details, mood.message);

  return {
    mood: mood.level,
    emoji,
    score: overallScore,
    details,
    tooltip,
  };
}

function analyzeNaming(text: string): number {
  const variablePattern = /(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g;
  const functionPattern = /(?:function|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=?/g;

  let goodNames = 0;
  let totalNames = 0;

  let match;
  while ((match = variablePattern.exec(text)) !== null) {
    totalNames++;
    const name = match[1];
    if (name.length >= 3 && !isSingleLetter(name)) {
      goodNames++;
    }
  }

  while ((match = functionPattern.exec(text)) !== null) {
    totalNames++;
    const name = match[1];
    if (name.length >= 3 && !isSingleLetter(name)) {
      goodNames++;
    }
  }

  return totalNames > 0 ? goodNames / totalNames : 0.5;
}

function isSingleLetter(name: string): boolean {
  return name.length === 1 && /^[a-z]$/i.test(name);
}

function calculateLineScore(metrics: any): number {
  const longLineRatio = metrics.veryLongLineCount / (metrics.codeLineCount || 1);
  const veryLongRatio = metrics.longLineCount / (metrics.codeLineCount || 1);

  if (longLineRatio > 0.5) return 0.3;
  if (longLineRatio > 0.2) return 0.5;
  if (veryLongRatio > 0.5) return 0.6;
  if (veryLongRatio > 0.2) return 0.8;
  return 1.0;
}

function calculateCommentScore(metrics: any): number {
  const ratio = metrics.commentLineCount / (metrics.totalLines || 1);
  if (ratio < 0.05) return 0.4;
  if (ratio < HEURISTICS.COMMENT_RATIO_IDEAL) return 0.9;
  if (ratio < HEURISTICS.COMMENT_RATIO_GOOD) return 0.8;
  return 0.7;
}

function calculateFunctionScore(metrics: any): number {
  if (metrics.avgFunctionLength > HEURISTICS.MAX_FUNCTION_LENGTH) return 0.3;
  if (metrics.avgFunctionLength > HEURISTICS.IDEAL_FUNCTION_LENGTH) return 0.7;
  return 1.0;
}

function calculateCleanliness(metrics: any): number {
  let score = 1.0;
  if (metrics.consoleLogCount > 0) score -= 0.1 * Math.min(metrics.consoleLogCount, 3);
  if (metrics.todoCount > 0) score -= 0.05 * Math.min(metrics.todoCount, 2);
  return Math.max(score, 0.2);
}

function determineMood(score: number): { level: CodeStyleMood["mood"]; message: string } {
  if (score >= 0.95) {
    return { level: "God-level", message: "Absolutely pristine! Your code is chef's kiss!" };
  } else if (score >= 0.85) {
    return { level: "Clean", message: "Well-organized and maintainable. Great job!" };
  } else if (score >= 0.65) {
    return { level: "Neat", message: "Decent code with room for improvement. Keep polishing!" };
  } else {
    return { level: "Messy", message: "Time for a code cleanup session. You got this!" };
  }
}

function getMoodEmoji(mood: CodeStyleMood["mood"]): string {
  const codeiconMap = {
    "God-level": "$(star-full)",
    Clean: "$(sparkle)",
    Neat: "$(beaker)",
    Messy: "$(warning)",
  };
  return codeiconMap[mood];
}

function formatLineMetric(metrics: any): string {
  const ratio = (metrics.veryLongLineCount / (metrics.codeLineCount || 1)) * 100;
  if (ratio > 50) return "$(error) Many very long lines";
  if (ratio > 20) return "$(warning) Some long lines";
  return "$(pass) Line lengths look good";
}

function formatCleanliness(metrics: any): string {
  if (metrics.consoleLogCount > 5 || metrics.todoCount > 3) return "$(error) Cleanup needed";
  if (metrics.consoleLogCount > 0 || metrics.todoCount > 0) return "$(warning) Minor issues";
  return "$(pass) Very clean";
}

function buildTooltip(details: any, message: string): string {
  return `${message}\n\n${details.lineLength}\n${details.naming}\n${details.comments}\n${details.functions}\n${details.complexity}`;
}
