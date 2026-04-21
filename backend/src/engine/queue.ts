import { Queue, QueueEvents } from 'bullmq';
import IORedis from 'ioredis';
import { env } from '../config/env';

// Redis connection setup
export const redisConnection = new IORedis({
  host: env.redisHost,
  port: env.redisPort,
  maxRetriesPerRequest: null,
});

export const SCENARIO_QUEUE_NAME = 'waap-scenario-execution';

// High-priority queue for immediate jobs
export const scenarioQueue = new Queue(SCENARIO_QUEUE_NAME, {
  connection: redisConnection,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 1000 },
    removeOnComplete: 1000,
    removeOnFail: 5000,
  },
});

export const scenarioQueueEvents = new QueueEvents(SCENARIO_QUEUE_NAME, {
  connection: redisConnection,
});
