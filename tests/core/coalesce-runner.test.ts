import { describe, it, expect } from 'vitest';
import { createCoalescingRunner } from '../../src/utils/coalesce-runner.js';

/** Promise that resolves when `release()` is called. */
function deferred(): { promise: Promise<void>; release: () => void } {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

describe('createCoalescingRunner (watch-mode pending flag)', () => {
  it('runs synchronous calls sequentially — no overlap', async () => {
    let active = 0;
    let maxActive = 0;
    let ran = 0;

    const run = createCoalescingRunner(async () => {
      active++;
      if (active > maxActive) maxActive = active;
      await new Promise<void>(resolve => setTimeout(resolve, 5));
      active--;
      ran++;
    });

    await Promise.all([run(), run(), run()]);

    expect(maxActive).toBe(1);
    // Because calls while in-flight are coalesced, the 2nd and 3rd calls
    // collapse into ONE trailing run — total of 2 runs.
    expect(ran).toBe(2);
  });

  it('coalesces 3 rapid trigger calls during an in-flight scan into exactly ONE trailing scan', async () => {
    // Simulates the audit scenario: fs.watch fires three times while the
    // initial scan is still running. We expect: initial scan + exactly ONE
    // follow-up, regardless of how many intervening triggers arrived.
    let ran = 0;
    const gate = deferred();

    const run = createCoalescingRunner(async () => {
      ran++;
      if (ran === 1) {
        // Pause the first run until we've queued up triggers behind it.
        await gate.promise;
      }
    });

    // Kick off the initial run (awaits gate).
    const initial = run();

    // Fire three triggers while initial is still pending.
    const t1 = run();
    const t2 = run();
    const t3 = run();

    // Release the initial run; coalesced follow-up should then execute once.
    gate.release();

    await Promise.all([initial, t1, t2, t3]);

    // 1 initial + 1 trailing coalesced = 2 total runs.
    expect(ran).toBe(2);
  });

  it('multiple waves of triggers each produce one trailing scan', async () => {
    // Wave 1: trigger a, b arrive during run 1. After run 1 completes, the
    // coalescer should execute exactly ONE trailing run (run 2).
    // Wave 2: after run 2 finishes, a fresh trigger c starts run 3.
    let ran = 0;
    const gates: Array<ReturnType<typeof deferred>> = [
      deferred(), deferred(), deferred(),
    ];

    const run = createCoalescingRunner(async () => {
      const idx = ran;
      ran++;
      await gates[idx].promise;
    });

    const initial = run();
    const a = run();       // coalesced into wave-1 trailing
    const b = run();       // coalesced into wave-1 trailing

    // Release run 1; run 2 (coalesced from a, b) starts and waits on gates[1].
    gates[0].release();

    // Wait until run 2 has actually started (ran advanced to 2).
    await new Promise<void>(resolve => {
      const tick = () => (ran >= 2 ? resolve() : setImmediate(tick));
      tick();
    });

    // Release run 2.
    gates[1].release();

    // Wait for initial/a/b to fully settle.
    await Promise.all([initial, a, b]);

    // Wave 2: now the runner is idle. Fire c; it should execute run 3.
    const c = run();
    gates[2].release();
    await c;

    // run 1 (initial) + run 2 (wave-1 coalesce) + run 3 (wave 2) = 3.
    expect(ran).toBe(3);
  });

  it('propagates via finally — an error in work does not wedge the runner', async () => {
    let ran = 0;
    const run = createCoalescingRunner(async () => {
      ran++;
      if (ran === 1) throw new Error('boom');
    });

    await expect(run()).rejects.toThrow('boom');
    // Next call should execute fresh (not stuck because scanning was left true).
    await run();
    expect(ran).toBe(2);
  });
});
