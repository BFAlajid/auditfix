/**
 * Coalescing runner for fs.watch-driven scan loops.
 *
 * Problem: fs.watch can fire many change events while a scan is in flight.
 * The prior `let scanning = false` guard silently dropped every event that
 * arrived during a scan, so the final lockfile state could go unchecked.
 *
 * Solution: if trigger() is called during an in-flight run, set `pending`
 * and run exactly one more scan after the current one completes — regardless
 * of how many events arrived. Further events during that trailing scan fold
 * back into the same flag.
 */
export type Runner = () => Promise<void>;

export function createCoalescingRunner(work: Runner): Runner {
  let scanning = false;
  let pending = false;

  return async () => {
    if (scanning) {
      pending = true;
      return;
    }
    scanning = true;
    try {
      do {
        pending = false;
        await work();
      } while (pending);
    } finally {
      scanning = false;
    }
  };
}
