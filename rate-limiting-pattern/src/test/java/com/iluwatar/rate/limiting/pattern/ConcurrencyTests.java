package com.iluwatar.rate.limiting.pattern;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ConcurrencyTests {
  @Test
  void tokenBucketShouldHandleConcurrentRequests() throws Exception {
    int threadCount = 10;
    int requestLimit = 5;
    RateLimiter limiter = new TokenBucketRateLimiter(requestLimit, requestLimit);
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    CountDownLatch latch = new CountDownLatch(threadCount);

    AtomicInteger successCount = new AtomicInteger();
    AtomicInteger failureCount = new AtomicInteger();

    try {
      for (int i = 0; i < threadCount; i++) {
        executor.submit(
            () -> {
              try {
                limiter.check("test", "op");
                successCount.incrementAndGet();
              } catch (RateLimitException e) {
                failureCount.incrementAndGet();
              } finally {
                latch.countDown();
              }
            });
      }

      assertTrue(latch.await(5, TimeUnit.SECONDS), "Timed out waiting for concurrent requests");
      assertEquals(requestLimit, successCount.get());
      assertEquals(threadCount - requestLimit, failureCount.get());
    } finally {
      executor.shutdown();
      if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
        executor.shutdownNow();
      }
    }
  }

  @Test
  void adaptiveLimiterShouldAdjustUnderLoad() throws Exception {
    AdaptiveRateLimiter limiter = new AdaptiveRateLimiter(10, 20);
    ExecutorService executor = Executors.newFixedThreadPool(20);
    CountDownLatch latch = new CountDownLatch(30);

    try {
      // Flood with requests to trigger throttling
      for (int i = 0; i < 30; i++) {
        executor.submit(
            () -> {
              try {
                limiter.check("test", "op");
              } catch (RateLimitException ignored) {
              } finally {
                latch.countDown();
              }
            });
      }

      assertTrue(latch.await(5, TimeUnit.SECONDS), "Timed out waiting for flood requests");

      // Verify new limit is in effect, polling until adjustment is observed or timing out.
      int allowed = 0;
      long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
      do {
        allowed = 0;
        for (int i = 0; i < 20; i++) {
          try {
            limiter.check("test", "op");
            allowed++;
          } catch (RateLimitException ignored) {
          }
        }

        if (allowed > 5 && allowed < 15) {
          break;
        }

        TimeUnit.MILLISECONDS.sleep(100);
      } while (System.nanoTime() < deadlineNanos);

      assertTrue(allowed > 5 && allowed < 15); // Should be between initial and max
    } finally {
      executor.shutdown();
      if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
        executor.shutdownNow();
      }
    }
  }
}
