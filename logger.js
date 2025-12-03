// logger.js
export function logEvent(message) {
  console.log(`[EVENT] ${message}`);
}

export function logError(error) {
  console.error(`[ERROR] ${error}`);
}

export function logScore(score) {
  console.log(`[SCORE] Current score: ${score}`);
}
