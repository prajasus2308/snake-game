// main.js
import { GAME_SETTINGS } from './config.js';
import { logEvent, logError, logScore } from './logger.js';

const canvas = document.getElementById("gameCanvas");
const ctx = canvas.getContext("2d");

// Resize canvas to full screen
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

const tileCountX = Math.floor(canvas.width / GAME_SETTINGS.gridSize);
const tileCountY = Math.floor(canvas.height / GAME_SETTINGS.gridSize);

let snake = [{ x: Math.floor(tileCountX / 2), y: Math.floor(tileCountY / 2) }];
let direction = { x: 0, y: 0 };
let food = spawnFood();
let score = 0;

function spawnFood() {
  return {
    x: Math.floor(Math.random() * tileCountX),
    y: Math.floor(Math.random() * tileCountY)
  };
}

function drawGame() {
  ctx.fillStyle = GAME_SETTINGS.backgroundColor;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Draw food
  ctx.fillStyle = GAME_SETTINGS.foodColor;
  ctx.fillRect(food.x * GAME_SETTINGS.gridSize, food.y * GAME_SETTINGS.gridSize, GAME_SETTINGS.gridSize, GAME_SETTINGS.gridSize);

  // Move snake
  const head = { x: snake[0].x + direction.x, y: snake[0].y + direction.y };
  snake.unshift(head);

  if (head.x === food.x && head.y === food.y) {
    food = spawnFood();
    score++;
    logScore(score);
  } else {
    snake.pop();
  }

  // Collision check
  if (
    head.x < 0 || head.x >= tileCountX ||
    head.y < 0 || head.y >= tileCountY ||
    snake.slice(1).some(segment => segment.x === head.x && segment.y === head.y)
  ) {
    logError("Game Over!");
    alert("Game Over! Score: " + score);
    snake = [{ x: Math.floor(tileCountX / 2), y: Math.floor(tileCountY / 2) }];
    direction = { x: 0, y: 0 };
    score = 0;
    food = spawnFood();
  }

  // Draw snake
  ctx.fillStyle = GAME_SETTINGS.snakeColor;
  snake.forEach(segment => {
    ctx.fillRect(segment.x * GAME_SETTINGS.gridSize, segment.y * GAME_SETTINGS.gridSize, GAME_SETTINGS.gridSize, GAME_SETTINGS.gridSize);
  });

  setTimeout(drawGame, GAME_SETTINGS.gameSpeed);
}

document.addEventListener("keydown", (e) => {
  switch (e.key) {
    case "ArrowUp":
    case "w":
      if (direction.y === 0) direction = { x: 0, y: -1 };
      break;
    case "ArrowDown":
    case "s":
      if (direction.y === 0) direction = { x: 0, y: 1 };
      break;
    case "ArrowLeft":
    case "a":
      if (direction.x === 0) direction = { x: -1, y: 0 };
      break;
    case "ArrowRight":
    case "d":
      if (direction.x === 0) direction = { x: 1, y: 0 };
      break;
  }
});

logEvent("Game started");
drawGame();
