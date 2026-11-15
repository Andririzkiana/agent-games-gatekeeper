import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

// Persistent seen-set of proof_tx references. PROOF_REUSED detection
// (Proof Gatekeeper trap #3) requires remembering every proof reference
// across tasks AND restarts, so this is file-backed, not in-memory only.

export class SeenSet {
  constructor(filePath) {
    this.filePath = filePath;
    this.set = new Set();
    if (existsSync(filePath)) {
      try {
        for (const line of readFileSync(filePath, 'utf8').split('\n')) {
          const v = line.trim();
          if (v) this.set.add(v);
        }
      } catch {
        // Corrupt seen-file: start empty rather than crash; reuse detection
        // degrades but decisions continue (documented trade-off).
      }
    }
  }

  has(v) {
    return this.set.has(v);
  }

  add(v) {
    if (this.set.has(v)) return;
    this.set.add(v);
    mkdirSync(dirname(this.filePath), { recursive: true });
    writeFileSync(this.filePath, [...this.set].join('\n') + '\n', 'utf8');
  }

  get size() {
    return this.set.size;
  }
}
